module Firerule.Port(Port, parsePort) where

import qualified Text.Parsec as Parsec
import Data.Word(Word16)

import qualified Firerule.IPParser as IPParse

type Port = Word16

parsePort :: String -> Either String Port
parsePort inp =
    case Parsec.parse port "inp" inp of
      Right addr -> Right addr
      Left v -> Left $ "port parse failed: " ++ (show v)

port = IPParse.integer
