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
import qualified FireruleMonitor.NetInfo as NetInfo

data DBusNetMonitor =
    DBusNetMonitor DC.Client DC.SignalHandler
        (IORef.IORef (Maybe NM.EventCallback))

data DBusNetNotifier = DBusNetNotifier DC.Client
    (IORef.IORef NotifierState)

newtype NotifierState = NotifierState {
        notifierFirewall :: Maybe String
    }

initNetMonitor client = do
   callbackRef <- IORef.newIORef Nothing
   signalHandler <- addHandler client
        (handlePropertiesChange client callbackRef)
   return $ DBusNetMonitor client signalHandler callbackRef
destroyNetMonitor (DBusNetMonitor client signalHandler _) =
    DC.removeMatch client signalHandler

initNetNotifier client = do
    res <- DC.requestName client (D.busName_ notifierBus)
        [DC.nameAllowReplacement, DC.nameReplaceExisting, DC.nameDoNotQueue]
    case res of
      DC.NamePrimaryOwner -> do
          state <- IORef.newIORef (NotifierState Nothing)
          let handle = DBusNetNotifier client state
          DC.export client notifierPath $ DC.defaultInterface
              {
                DC.interfaceName = notifierInterface,
                DC.interfaceProperties =
                    [
                    DC.readOnlyProperty
                        (D.memberName_ notifierFirewallProperty)
                        (notifierPropertyGet handle)
                    ]
              }
          return handle
      _ -> fail "failed to init notifier"
destroyNetNotifier (DBusNetNotifier client _) = do
    res <- DC.releaseName client (D.busName_ notifierBus)
    case res of
      DC.NameReleased -> return ()
      _ -> fail "failed to destroy notifier"

instance NM.NetMonitor DBusNetMonitor where
    info (DBusNetMonitor client _ _) = getActiveConnections client
    listen (DBusNetMonitor client _ handler) = IORef.writeIORef handler

instance NM.NetNotifier DBusNetNotifier where
    netRuleChanged (DBusNetNotifier client state) firewall = do
        IORef.modifyIORef' state (\_ -> NotifierState (Just firewall))
        DC.emit client $
            (D.signal notifierPath propertiesInterface "PropertiesChanged")
            {
                D.signalBody = [
                    D.toVariant notifierInterface,
                    D.toVariant
                        (Map.singleton notifierFirewallProperty
                            (D.toVariant firewall)),
                    D.toVariant ([] :: [String])
                ]
            }

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
        (D.methodCall object propertiesInterface
            (D.memberName_ "Get")) {
        D.methodCallDestination = Just dest,
        D.methodCallBody = [D.toVariant interface, D.toVariant property]
        }
    let res = exactlyOneFromList (D.methodReturnBody reply)
            >>= variantValue >>= variantValue
    case res of
      Left err -> fail err
      Right v -> return v

getInfo client = (fmap NetInfo.NetInfo) .
    (Monad.mapM (\c -> getProperty client nmdest c
                ("org.freedesktop.NetworkManager.Connection.Active" :: String)
                ("Id" :: String)))

removeHandler = DC.removeMatch

addHandler client =
    DC.addMatch client DC.matchAny
    {
        DC.matchPath = Just "/org/freedesktop/NetworkManager",
        DC.matchInterface = Just propertiesInterface,
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

notifierPropertyGet (DBusNetNotifier _ state) = do
    state <- IORef.readIORef state
    return $ Maybe.fromMaybe "" $ notifierFirewall state

nmdest = "org.freedesktop.NetworkManager"

propertiesInterface = "org.freedesktop.DBus.Properties"

notifierBus = "org.polymya.FireruleMonitor"
notifierInterface = "org.polymya.FireruleMonitor"
notifierPath = "/org/polymya/FireruleMonitor"

notifierFirewallProperty = "firewall"
