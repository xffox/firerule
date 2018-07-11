module Firerule.Iptables.Iptables(
    IptablesFirewall(..), IptablesTreeFirewall(..)) where

import qualified Data.List as List
import qualified System.Process as Process
import qualified System.Exit as Exit

import qualified Firerule.Conf as Conf
import qualified Firerule.CondTree as CondTree
import qualified Firerule.Firewall as Firewall
import qualified Firerule.Iptables.IptablesBuilder as IptablesBuilder

data IptablesFirewall = IptablesFirewall

instance Firewall.Firewall IptablesFirewall where
    apply _ fw = do
        let commands = IptablesBuilder.buildCommands fw
        mapM_ execCommand cleanupCommands
        mapM_ execCommand commands

data IptablesTreeFirewall = IptablesTreeFirewall

instance Firewall.Firewall IptablesTreeFirewall where
    apply _ (Conf.Firewall rules) = do
        let netrules = IptablesBuilder.perNetworkRules rules
        mapM_
            (putStrLn . CondTree.showTree . IptablesBuilder.iptablesSimplify) $
                concatMap (\(_, _, acts) -> map snd acts) $
                    concatMap snd netrules

execCommand v@(cmd, args) = do
    res <- Process.rawSystem cmd args
    case res of
      Exit.ExitSuccess -> return ()
      Exit.ExitFailure code -> fail "execution failed"

cleanupCommands = concatMap (\cmd -> map ((,) cmd) cleanupArgs) $
    map IptablesBuilder.networkToCommand $
        [minBound :: IptablesBuilder.NetworkMatch .. maxBound]

cleanupArgs = [
        ["-t", "filter", "-F"],
        ["-t", "filter", "-P", "INPUT", "ACCEPT"],
        ["-t", "filter", "-P", "OUTPUT", "ACCEPT"],
        ["-t", "filter", "-P", "FORWARD", "ACCEPT"]
    ]
