module FireruleMonitor.NetInfo(NetInfo(..)) where

newtype NetInfo = NetInfo {
    networks :: [String]
    }
    deriving Show

