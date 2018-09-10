module NetRuleExecutor(NetRuleHandle, runNetRule, stopNetRule) where

import qualified Data.List as List
import qualified Text.Printf as Printf
import qualified Control.Concurrent.MVar as MVar
import qualified Control.Exception as Exception

import qualified Firerule.CondTree as CT
import qualified Firerule.Firewall as Firewall
import qualified Firerule.Iptables.Iptables as Iptables
import qualified NetMonitor as NM
import qualified NetRule as NetRule

data NetRuleHandle m n = NetRuleHandle m n (MVar.MVar ())

callback nr monitor notifier lock (NM.NetworkChange info) =
    handleNetwork nr monitor notifier lock

runNetRule :: (NM.NetMonitor m, NM.NetNotifier n) =>
    m -> n -> NetRule.NetRule -> IO (NetRuleHandle m n)
runNetRule monitor notifier nr = do
    putStrLn $ "starting monitor"
    lock <- MVar.newMVar ()
    NM.listen monitor (Just (callback nr monitor notifier lock))
    handleNetwork nr monitor notifier lock
    return $ NetRuleHandle monitor notifier lock

stopNetRule :: (NM.NetMonitor m, NM.NetNotifier n) =>
    (NetRuleHandle m n) -> IO ()
stopNetRule (NetRuleHandle monitor _ lock) = do
    putStrLn $ "stopping monitor"
    NM.listen monitor Nothing
    MVar.takeMVar lock

handleNetwork nr monitor notifier lock =
    Exception.bracket_
        (MVar.takeMVar lock)
        (MVar.putMVar lock ())
        (do
            info <- NM.info monitor
            logNetInfo info
            let (name, fw) = selectNetRule info nr
            putStrLn $ Printf.printf "applying firewall: '%s'" name
            Firewall.apply Iptables.IptablesFirewall $ fw
            putStrLn $ Printf.printf "applied firewall: '%s'" name
            NM.netRuleChanged notifier name
        )

selectNetRule info (NetRule.NetRule defaultFirewall rules) =
    case List.find (evalTree info . snd) rules of
      Just (firewall, _) -> firewall
      _ -> defaultFirewall

evalTree info (CT.Leaf cnd) =
    evalCondition info cnd
evalTree info (CT.NodeOr left right) =
    evalTree info left || evalTree info right
evalTree info (CT.NodeAnd left right) =
    evalTree info left && evalTree info right
evalTree info (CT.NodeNot node) =
    not $ evalTree info node
evalTree info CT.NodeTrue =
    True
evalTree info CT.NodeFalse =
    False

evalCondition (NM.Info [actualConnection])
    (NetRule.ConnectionName connection) = actualConnection == connection
evalCondition _ _ = False

logNetInfo (NM.Info connections) =
    putStrLn $ Printf.printf "current connections: %s" $
        unwords $ map (\c -> Printf.printf "'%s'" c) connections
