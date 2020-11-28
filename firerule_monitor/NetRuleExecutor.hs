module NetRuleExecutor(NetRuleHandle, runNetRule, stopNetRule) where

import qualified Data.List as List
import qualified Data.Set as Set
import qualified Text.Printf as Printf
import qualified Control.Concurrent.MVar as MVar
import qualified Control.Exception as Exception

import qualified Firerule.CondTree as CT
import qualified Firerule.Firewall as Firewall
import qualified Firerule.Iptables.Iptables as Iptables
import qualified Firerule.BoolPair as BoolPair
import qualified Firerule.Conf as Conf
import qualified FireruleMonitor.NetRule as NetRule
import qualified FireruleMonitor.NetInfo as NetInfo
import qualified NetMonitor as NM

data NetRuleHandle m n = NetRuleHandle m n (MVar.MVar ())

callback fh selector handle (NM.NetworkChange info) =
    handleNetwork fh selector handle

runNetRule :: (NM.NetMonitor m, NM.NetNotifier n, Firewall.Firewall f r) =>
    f -> m -> n -> NetRule.NetRule (String, r) -> IO (NetRuleHandle m n)
runNetRule fh monitor notifier nr = do
    -- TODO: handle errors
    let selector = NetRule.makeSelector nr
    putStrLn "starting monitor"
    lock <- MVar.newMVar ()
    let handle = NetRuleHandle monitor notifier lock
    NM.listen monitor (Just (callback fh selector handle))
    handleNetwork fh selector handle
    return handle

stopNetRule :: (NM.NetMonitor m, NM.NetNotifier n) =>
    NetRuleHandle m n -> IO ()
stopNetRule (NetRuleHandle monitor _ lock) = do
    putStrLn "stopping monitor"
    NM.listen monitor Nothing
    MVar.takeMVar lock

handleNetwork fh selector (NetRuleHandle monitor notifier lock) =
    Exception.bracket_
        (MVar.takeMVar lock)
        (MVar.putMVar lock ())
        (do
            info <- NM.info monitor
            logNetInfo info
            case NetRule.selectNetRule selector info of
              (Just (name, fw)) -> do
                  putStrLn $ Printf.printf "applying firewall: '%s'" name
                  Firewall.use fh fw
                  putStrLn $ Printf.printf "applied firewall: '%s'" name
                  NM.netRuleChanged notifier name
              _ -> undefined
        )

logNetInfo (NetInfo.NetInfo connections) =
    putStrLn $ Printf.printf "current connections: %s" $
        unwords $ map (\c -> Printf.printf "'%s'" c) connections
