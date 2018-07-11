module Firerule.Format.ConfBuilder(buildConf) where

import qualified Text.Printf as Printf
import qualified Data.List as List

import qualified Firerule.Conf as Conf
import qualified Firerule.IPv4 as IPv4
import qualified Firerule.IPv6 as IPv6
import qualified Firerule.Port as Port
import qualified Firerule.CondTree as CT
import qualified Firerule.Format.PrefixTree as PrefixTree
import qualified Firerule.Format.RuleParser as RuleParser

buildConf :: RuleParser.Firewall -> Either String Conf.Firewall
buildConf (RuleParser.Firewall rules) =
    fmap Conf.Firewall $ mapM buildRule rules

buildRule (RuleParser.Rule flow jumps) =
    let (defaultJumps, actJumps) = List.partition isDefaultJump jumps
     in case defaultJumps of
          [RuleParser.DefaultJump act] -> Conf.Rule <$>
              (buildFlow flow) <*>
                  (buildAction act) <*>
                      (mapM buildJump actJumps)
          _ -> Left "invalid default jump"

buildFlow flow =
    case flow of
      "input" -> Right Conf.Input
      "output" -> Right Conf.Output
      "forward" -> Right Conf.Forward

buildAction act =
    case act of
      "drop" -> Right Conf.Drop
      "accept" -> Right Conf.Accept
      "reject" -> Right Conf.Reject

buildJump (RuleParser.Jump act tr) = (,) <$> (buildAction act) <*>
    buildRuleClause tr
buildJump _ = fail "invalid jump"

buildRuleClause tr = fmap Conf.RuleClause $
    mapM buildCondition tr

buildCondition (RuleParser.Condition as@(ns:args)) = do
    ns' <- RuleParser.parseNamespace ns
    case PrefixTree.findPrefix ns' conditions of
      Just b -> b args
      _ -> fail $ Printf.printf "condition not found: %s" (show as)
buildCondition _ = fail "invalid condition clause"

isDefaultJump (RuleParser.DefaultJump _) = True
isDefaultJump _ = False

buildInterface [dir, name] = fmap Conf.LayerCondition $
    Conf.DirectedLayer <$> (buildDirection dir) <*>
        (pure $ Conf.LinkLayer $ Conf.MACInterface $ Conf.MacAddr name)

buildIPv4 [dir] = fmap Conf.LayerCondition $
    Conf.DirectedLayer <$> (buildDirection dir) <*>
        (pure $ Conf.NetworkLayer Conf.ipv4)
buildIPv4 _  = Left "invalid ipv4 args"

buildIPv6 [dir] = fmap Conf.LayerCondition $
    Conf.DirectedLayer <$> (buildDirection dir) <*>
        (pure $ Conf.NetworkLayer Conf.ipv6)
buildIPv6 _  = Left "invalid ipv6 args"

buildIPv4Addr [dir, addr] = fmap Conf.LayerCondition $
    Conf.DirectedLayer <$> (buildDirection dir) <*>
        (fmap (Conf.NetworkLayer . Conf.ipv4Addr) (IPv4.parseIPv4 addr))
buildIPv4Addr _  = Left "invalid ipv4 args"

buildIPv4ICMP [] = return $ Conf.LayerCondition $
    Conf.DirectedLayer Conf.Any $ Conf.NetworkLayer Conf.icmp

buildIPv6Addr [dir, addr] = fmap Conf.LayerCondition $
    Conf.DirectedLayer <$> (buildDirection dir) <*>
        (fmap (Conf.NetworkLayer . Conf.ipv6Addr) (IPv6.parseIPv6 addr))
buildIPv6Addr _  = Left "invalid ipv6 args"

buildIPv6ICMP [] = return $ Conf.LayerCondition $
    Conf.DirectedLayer Conf.Any $ Conf.NetworkLayer Conf.icmpv6

buildTCP [dir] = fmap Conf.LayerCondition $
    Conf.DirectedLayer <$> (buildDirection dir) <*>
        (pure $ Conf.TransportLayer Conf.tcp)
buildTCP _ =  Left "invalid TCP args"

buildTCPPort [dir, port] = fmap Conf.LayerCondition $
    Conf.DirectedLayer <$> (buildDirection dir) <*>
        (fmap (Conf.TransportLayer . Conf.tcpPort) (Port.parsePort port))
buildTCPPort _ = Left "invalid TCP port args"

buildUDP [dir] = fmap Conf.LayerCondition $
    Conf.DirectedLayer <$> (buildDirection dir) <*>
        (pure $ Conf.TransportLayer Conf.udp)
buildUDP _ =  Left "invalid UDP args"

buildUDPPort [dir, port] = fmap Conf.LayerCondition $
    Conf.DirectedLayer <$> (buildDirection dir) <*>
        (fmap (Conf.TransportLayer . Conf.udpPort) (Port.parsePort port))
buildUDPPort _ = Left "invalid UDP port args"

buildDirection dir =
    case dir of
      "src" -> Right $ Conf.Src
      "dst" -> Right $ Conf.Dst
      "any" -> Right $ Conf.Any
      _ -> Left "unknown direction"

buildConnectionState [state] = fmap Conf.StateCondition $ buildState state
buildConnectionState _ = fail "invalid connection state args"

buildState "related" = Right $ Conf.StateRelated
buildState "established" = Right $ Conf.StateEstablished
buildState _ = Left "unknown connection state"

conditions = PrefixTree.buildPrefixTree $ do
    PrefixTree.appendPrefix ["layer", "link", "if"] buildInterface
    PrefixTree.appendPrefix ["layer", "net", "ipv4"] buildIPv4
    PrefixTree.appendPrefix ["layer", "net", "ipv4", "addr"] buildIPv4Addr
    PrefixTree.appendPrefix ["layer", "net", "ipv4", "icmp"] buildIPv4ICMP
    PrefixTree.appendPrefix ["layer", "net", "ipv6"] buildIPv6
    PrefixTree.appendPrefix ["layer", "net", "ipv6", "addr"] buildIPv6Addr
    PrefixTree.appendPrefix ["layer", "net", "ipv6", "icmp"] buildIPv6ICMP
    PrefixTree.appendPrefix ["layer", "transport", "tcp"] buildTCP
    PrefixTree.appendPrefix ["layer", "transport", "tcp", "port"] buildTCPPort
    PrefixTree.appendPrefix ["layer", "transport", "udp"] buildUDP
    PrefixTree.appendPrefix ["layer", "transport", "udp", "port"] buildUDPPort
    PrefixTree.appendPrefix ["state", "connection"] buildConnectionState
