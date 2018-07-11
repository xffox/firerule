module NetRuleExecutor where

import qualified Data.List as List
import qualified Text.Printf as Printf

import qualified Firerule.CondTree as CT
import qualified Firerule.Firewall as Firewall
import qualified Firerule.Iptables.Iptables as Iptables
import qualified DBusNetMonitor as DBusNetMonitor
import qualified NetMonitor as NM
import qualified NetRule as NetRule

data NetRuleHandle = NetRuleHandle DBusNetMonitor.DBusNetMonitor

callback nr (NM.NetworkChange info) =
    handleNetwork nr info

stopNetRule (NetRuleHandle monitor) = NM.destroy monitor

runNetRule nr = do
    monitor <- NM.init :: IO DBusNetMonitor.DBusNetMonitor
    NM.listen monitor (Just (callback nr))
    info <- NM.info monitor
    handleNetwork nr info
    return $ NetRuleHandle monitor

handleNetwork nr info = do
    logNetInfo info
    let (name, fw) = selectNetRule info nr
    putStrLn $ Printf.printf "applying firewall: '%s'" name
    Firewall.apply Iptables.IptablesFirewall $ fw
    putStrLn $ Printf.printf "applied firewall: '%s'" name

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
