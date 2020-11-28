module NetMonitor where

import qualified FireruleMonitor.NetInfo as NetInfo

newtype Event =
    NetworkChange NetInfo.NetInfo

type EventCallback = Event -> IO ()

class NetMonitor m where
    info :: m -> IO NetInfo.NetInfo
    listen :: m -> Maybe EventCallback -> IO ()

class NetNotifier n where
    netRuleChanged :: n -> String -> IO ()
