{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Firerule.Iptables.Iptables(
    IptablesFirewall(..), IptablesTreeFirewall(..),
    IptablesPrintFirewall(..)) where

import qualified Data.List as List
import qualified System.Process as Process
import qualified System.Exit as Exit
import qualified Control.DeepSeq as DeepSeq

import qualified Firerule.Conf as Conf
import qualified Firerule.CondTree as CondTree
import qualified Firerule.Firewall as Firewall
import qualified Firerule.Iptables.IptablesBuilder as IptablesBuilder

data IptablesFirewall = IptablesFirewall

instance Firewall.Firewall
    IptablesFirewall IptablesBuilder.IptablesCommands where
    create _ fw = return $ IptablesBuilder.buildCommands fw
    use _ commands  = do
        let cmds = cleanupCommands ++ commands
        cmds `DeepSeq.deepseq` mapM_ execCommand cmds

data IptablesTreeFirewall = IptablesTreeFirewall

instance Firewall.Firewall IptablesTreeFirewall Conf.Firewall where
    create _ = return
    use _ (Conf.Firewall rules) = do
        let netrules = IptablesBuilder.perNetworkRules rules
        mapM_
            (putStrLn . CondTree.showTree . IptablesBuilder.iptablesSimplify) $
                concatMap (\(_, _, acts) -> map snd acts) $
                    concatMap snd netrules

data IptablesPrintFirewall = IptablesPrintFirewall

instance Firewall.Firewall IptablesPrintFirewall Conf.Firewall where
    create _ = return
    use _ fw =
        mapM_ printCommand $ IptablesBuilder.buildCommands fw

execCommand v@(cmd, args) = do
    res <- Process.rawSystem cmd args
    case res of
      Exit.ExitSuccess -> return ()
      Exit.ExitFailure code -> fail "execution failed"

printCommand (cmd, args) =
    putStrLn $ unwords (cmd:args)

cleanupCommands = concatMap (\cmd -> map ((,) cmd) cleanupArgs) $
    map IptablesBuilder.networkToCommand $
        [minBound :: IptablesBuilder.NetworkMatch .. maxBound]

cleanupArgs = [
        ["-t", "filter", "-F"],
        ["-t", "filter", "-P", "INPUT", "ACCEPT"],
        ["-t", "filter", "-P", "OUTPUT", "ACCEPT"],
        ["-t", "filter", "-P", "FORWARD", "ACCEPT"]
    ]
