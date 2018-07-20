module NetMonitor where

data Event =
    NetworkChange Info

data Info = Info {
    networks :: [String]
    }
    deriving Show

type EventCallback = Event -> IO ()

class NetMonitor m where
    info :: m -> IO Info
    listen :: m -> (Maybe EventCallback) -> IO ()

class NetNotifier n where
    netRuleChanged :: n -> String -> IO ()
