module NetMonitor where

data Event =
    NetworkChange Info

data Info = Info {
    networks :: [String]
    }
    deriving Show

type EventCallback = Event -> IO ()

class NetMonitor m where
    init :: IO m
    destroy :: m -> IO ()
    info :: m -> IO Info
    listen :: m -> (Maybe EventCallback) -> IO ()
