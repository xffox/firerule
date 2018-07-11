{-# LANGUAGE OverloadedStrings #-}
module DBusNetMonitor where

import qualified Control.Monad as Monad
import qualified Data.Maybe as Maybe
import qualified Data.Map.Lazy as Map
import qualified Data.IORef as IORef
import Control.Applicative((<|>))

import qualified DBus as D
import qualified DBus.Client as DC

import qualified NetMonitor as NM

data DBusNetMonitor = DBusNetMonitor DC.Client (IORef.IORef (Maybe NM.EventCallback))

nmdest = "org.freedesktop.NetworkManager"

instance NM.NetMonitor DBusNetMonitor where
    init = do
       client <- DC.connectSystem
       callbackRef <- IORef.newIORef Nothing
       addHandler client (handlePropertiesChange client callbackRef)
       return $ DBusNetMonitor client callbackRef
    destroy (DBusNetMonitor client _) = DC.disconnect client
    info (DBusNetMonitor client _) = getActiveConnections client
    listen (DBusNetMonitor client handler) mf =
        IORef.writeIORef handler mf

handlePropertiesChange client callbackRef signal = do
    mbCallback <- IORef.readIORef callbackRef
    case mbCallback of
      Just callback -> do
          res <- valueOrFail $ processActiveConnectionsSignal $
              D.signalBody signal
          case res of
            Right (Just connections) -> do
                netinfo <- getInfo client connections
                callback $ NM.NetworkChange $ netinfo
            Right Nothing -> do
                netinfo <- getActiveConnections client
                callback $ NM.NetworkChange $ netinfo
            Left () -> return ()
      Nothing -> return ()

getActiveConnections client = do
    connections <- getProperty client nmdest
            "/org/freedesktop/NetworkManager"
            ("org.freedesktop.NetworkManager" :: String)
            ("ActiveConnections" :: String)
    getInfo client connections

getProperty client dest object interface property = do
    reply <- DC.call_ client
        (D.methodCall object "org.freedesktop.DBus.Properties"
            (D.memberName_ "Get")) {
        D.methodCallDestination = Just dest,
        D.methodCallBody = [D.toVariant interface, D.toVariant property]
        }
    let res = exactlyOneFromList (D.methodReturnBody reply)
            >>= variantValue >>= variantValue
    case res of
      Left err -> fail err
      Right v -> return v

getInfo client = (fmap NM.Info) .
    (Monad.mapM (\c -> getProperty client nmdest c
                ("org.freedesktop.NetworkManager.Connection.Active" :: String)
                ("Id" :: String)))

removeHandler = DC.removeMatch

addHandler client =
    DC.addMatch client DC.matchAny
    {
        DC.matchPath = Just "/org/freedesktop/NetworkManager",
        DC.matchInterface = Just "org.freedesktop.DBus.Properties",
        DC.matchMember = Just "PropertiesChanged"
    }

processActiveConnectionsSignal body =
    case body of
      [interfaceVariant, inlinePropertiesVariant, propertiesVariant] -> do
            interface <- variantValue interfaceVariant
            properties <- variantValue propertiesVariant :: Either String [String]
            if interface == ("org.freedesktop.NetworkManager" :: String)
               then (fmap (Right . Just) $ variantValueByName
                ("ActiveConnections" :: String) inlinePropertiesVariant
                    >>= variantValue)
                <|> (if elem ("ActiveConnections" :: String) properties
                        then return $ Right Nothing
                        else return $ Left ())
            else return $ Left ()
      _ -> Left "invalid body"

variantValue var =
    case D.fromVariant var of
      Just v -> Right v
      Nothing -> Left "invalid type"

variantValueByIdx idx var =
    let res = do
            lst <- D.fromVariant var
            if idx <= length lst
               then Just $ lst !! idx
               else Nothing
    in case res of
             Just v -> Right v
             Nothing -> Left "idx not found"

variantValueByName name var =
    let res = do
            dct <- D.fromVariant var
            Map.lookup name dct
    in case res of
         Just v -> Right v
         Nothing -> Left "name not found"

exactlyOneFromList lst
  | length lst == 1 = Right $ head lst
  | otherwise = Left "not exactly one element"

valueOrFail val =
    case val of
      Right v -> return v
      Left err -> fail err
