{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
module Firerule.Iptables.IptablesBuilder where

import Data.Word (Word16)
import qualified Data.Map as Map
import qualified Data.Set as Set
import qualified Data.List as List
import qualified Control.Monad as Monad
import qualified Data.Maybe as Maybe
import Control.Applicative((<|>))

import qualified Firerule.IPv4 as IPv4
import qualified Firerule.ValueSet as VS
import qualified Firerule.Conf as Conf
import qualified Firerule.Analyzer as Analyzer
import qualified Firerule.CondTree as CondTree
import qualified Firerule.Iptables.IptablesRuleState as IptablesRuleState
import qualified Firerule.Iptables.IptablesData as Data
import qualified Firerule.Iptables.MatchExpr as MatchExpr

type IptablesCommands = [(String, [String])]

buildCommands :: Conf.Firewall -> IptablesCommands
buildCommands = firewallToCommands

iptablesSimplify =
    Analyzer.simplify iptablesSimplifyOps treeMetric

iptablesCondTree :: CondTree.CondTree Conf.Condition ->
    (CondTree.CondTree MatchExpr.MatchExpr,
        CondTree.CondTree MatchExpr.MatchExpr)
iptablesCondTree CondTree.NodeTrue = (CondTree.NodeTrue, CondTree.NodeTrue)
iptablesCondTree CondTree.NodeFalse = (CondTree.NodeFalse, CondTree.NodeFalse)
iptablesCondTree (CondTree.NodeOr left right) =
    let (leftSubtree1, leftSubtree2) = iptablesCondTree left
        (rightSubtree1, rightSubtree2) = iptablesCondTree right
     in (CondTree.NodeOr leftSubtree1 rightSubtree1,
         CondTree.NodeOr leftSubtree2 rightSubtree2)
iptablesCondTree (CondTree.NodeAnd left right) =
    let (leftSubtree1, leftSubtree2) = iptablesCondTree left
        (rightSubtree1, rightSubtree2) = iptablesCondTree right
     in (CondTree.NodeAnd leftSubtree1 rightSubtree1,
         CondTree.NodeAnd leftSubtree2 rightSubtree2)
iptablesCondTree (CondTree.NodeNot n) =
    let (subtree1, subtree2) = iptablesCondTree n
     in (CondTree.NodeNot subtree1, CondTree.NodeNot subtree2)
iptablesCondTree (CondTree.Leaf v) =
    let (subtree1, subtree2) = conditionToMatch v
        tr = fmap (\(neg, v) -> Map.singleton (matchValueKey v) (neg, v))
     in (tr subtree1, tr subtree2)
    where
        conditionToMatch (Conf.LayerCondition v) = layerToMatch v
        conditionToMatch (Conf.StateCondition (_, v)) = stateToMatch v
        layerToMatch (Conf.DirectedLayer dir
            (neg, Conf.LinkLayer l)) = linkLayerToMatch dir neg l
        layerToMatch (Conf.DirectedLayer dir
            (neg, Conf.NetworkLayer l)) = netLayerToMatch dir neg l
        layerToMatch (Conf.DirectedLayer dir
            (neg, Conf.TransportLayer l)) = transportLayerToMatch dir neg l
        linkLayerToMatch dir neg (Conf.MACInterface p) =
            macParamToMatch dir neg p
        netLayerToMatch dir neg (Conf.IPv4Network p) =
            ipv4ParamToMatch dir neg p
        netLayerToMatch dir neg (Conf.IPv6Network p) =
            ipv6ParamToMatch dir neg p
        transportLayerToMatch dir neg (Conf.TCPTransport p) =
            tcpParamToMatch dir neg p
        transportLayerToMatch dir neg (Conf.UDPTransport p) =
            udpParamToMatch dir neg p
        macParamToMatch _ neg Conf.MacProto =
            let m = CondTree.NodeTrue
             in (m, m)
        macParamToMatch Conf.Src neg (Conf.MacAddr a) =
            let m = CondTree.Leaf (neg, Data.InInterface a)
             in (m, m)
        macParamToMatch Conf.Dst neg (Conf.MacAddr a) =
            let m = CondTree.Leaf (neg, Data.OutInterface a)
             in (m, m)
        macParamToMatch Conf.Any neg (Conf.MacAddr a) =
            let m = CondTree.NodeOr
                        (CondTree.Leaf (neg, Data.OutInterface a))
                        (CondTree.Leaf (neg, Data.InInterface a))
             in (m, m)
        ipv4ParamToMatch _ neg Conf.IPv4Proto =
               (CondTree.NodeTrue, CondTree.NodeFalse)
        ipv4ParamToMatch Conf.Src neg (Conf.IPv4Addr a) =
            (CondTree.Leaf (neg, Data.Source $ Data.IPv4 a),
                CondTree.NodeFalse)
        ipv4ParamToMatch Conf.Dst neg (Conf.IPv4Addr a) =
            (CondTree.Leaf (neg, Data.Destination $ Data.IPv4 a),
                CondTree.NodeFalse)
        ipv4ParamToMatch Conf.Any neg (Conf.IPv4Addr a) =
            (CondTree.NodeOr
                (CondTree.Leaf (neg, Data.Destination $ Data.IPv4 a))
                (CondTree.Leaf (neg, Data.Source $ Data.IPv4 a)),
                    CondTree.NodeFalse)
        ipv4ParamToMatch _ neg Conf.IPv4ICMP =
            (CondTree.Leaf (neg, Data.Protocol Data.ICMP),
                CondTree.NodeFalse)
        ipv6ParamToMatch _ neg Conf.IPv6Proto =
            (CondTree.NodeFalse, CondTree.NodeTrue)
        ipv6ParamToMatch Conf.Src neg (Conf.IPv6Addr a) =
            (CondTree.NodeFalse,
                CondTree.Leaf (neg, Data.Source $ Data.IPv6 a))
        ipv6ParamToMatch Conf.Dst neg (Conf.IPv6Addr a) =
            (CondTree.NodeFalse,
                CondTree.Leaf (neg, Data.Destination $ Data.IPv6 a))
        ipv6ParamToMatch Conf.Any neg (Conf.IPv6Addr a) =
            (CondTree.NodeFalse,
                CondTree.NodeOr
                    (CondTree.Leaf (neg, Data.Destination $ Data.IPv6 a))
                    (CondTree.Leaf (neg, Data.Source $ Data.IPv6 a)))
        ipv6ParamToMatch _ neg Conf.IPv6ICMP =
            (CondTree.NodeFalse,
                CondTree.Leaf (neg, Data.Protocol Data.ICMPv6))
        tcpParamToMatch _ neg Conf.TCPProto =
            let m = CondTree.Leaf (neg, Data.Protocol Data.TCP)
             in (m, m)
        tcpParamToMatch Conf.Src neg (Conf.TCPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (True, Data.Protocol Data.TCP))
                        (CondTree.Leaf (neg, Data.SrcPort p))
             in (m, m)
        tcpParamToMatch Conf.Dst neg (Conf.TCPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (True, Data.Protocol Data.TCP))
                        (CondTree.Leaf (neg, Data.DstPort p))
             in (m, m)
        tcpParamToMatch Conf.Any neg (Conf.TCPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (True, Data.Protocol Data.TCP))
                        (CondTree.NodeOr
                            (CondTree.Leaf (neg, Data.SrcPort p))
                            (CondTree.Leaf (neg, Data.DstPort p))
                            )
             in (m, m)
        udpParamToMatch _ neg Conf.UDPProto =
            let m = CondTree.Leaf (neg, Data.Protocol Data.UDP)
             in (m, m)
        udpParamToMatch Conf.Src neg (Conf.UDPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (True, Data.Protocol Data.UDP))
                        (CondTree.Leaf (neg, Data.SrcPort p))
             in (m, m)
        udpParamToMatch Conf.Dst neg (Conf.UDPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (True, Data.Protocol Data.UDP))
                        (CondTree.Leaf (neg, Data.DstPort p))
             in (m, m)
        udpParamToMatch Conf.Any neg (Conf.UDPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (True, Data.Protocol Data.UDP))
                        (CondTree.NodeOr
                            (CondTree.Leaf (neg, Data.SrcPort p))
                            (CondTree.Leaf (neg, Data.DstPort p))
                            )
             in (m, m)
        stateToMatch Conf.StateRelated =
            let m = CondTree.Leaf (True, Data.State $
                    Set.singleton Data.CtRelated)
             in (m, m)
        stateToMatch Conf.StateEstablished =
            let m = CondTree.Leaf (True, Data.State $
                    Set.singleton Data.CtEstablished)
             in (m, m)

data NetworkMatch = MatchIPv4 | MatchIPv6
    deriving (Eq, Ord, Enum, Bounded)

matchValueKey (Data.Source _) = MatchExpr.MatchSource
matchValueKey (Data.Destination _) = MatchExpr.MatchDestination
matchValueKey (Data.Protocol _) = MatchExpr.MatchProtocol
matchValueKey (Data.InInterface _) = MatchExpr.MatchInInterface
matchValueKey (Data.OutInterface _) = MatchExpr.MatchOutInterface
matchValueKey (Data.SrcPort _) = MatchExpr.MatchSrcPort
matchValueKey (Data.DstPort _) = MatchExpr.MatchDstPort
matchValueKey (Data.State _) = MatchExpr.MatchCtState

firewallToCommands :: Conf.Firewall -> [(String, [String])]
firewallToCommands (Conf.Firewall rules) =
    concatMap (\(net, rules) -> zip (repeat $ networkToCommand net)
        (concatMap step rules)) $ perNetworkRules rules
        where step (flow, action, acts) =
                IptablesRuleState.runRuleProducer $
                    ruleToCommands flow action acts

perNetworkRules rules =
    Map.toList $
        Map.fromListWith (++) $ concatMap perNetworkRule rules
    where
        perNetworkRule (Conf.Rule flow action acts) =
            map (\(k, v) -> (k, [v])) $ Map.toList $
                Map.map (\acts -> (flow, action, acts)) $
                    Map.fromListWith (++) $ perNetworkActions acts
        perNetworkActions [] = [(MatchIPv4, []), (MatchIPv6, [])]
        perNetworkActions acts = concatMap netAct acts
        netAct (act, Conf.RuleClause clause) =
            let (tr4, tr6) = iptablesCondTree clause
             in [(MatchIPv4, [(act, tr4)]), (MatchIPv6, [(act, tr6)])]

ruleToCommands :: Conf.Flow -> Conf.Action ->
    [(Conf.Action, CondTree.CondTree MatchExpr.MatchExpr)] ->
    IptablesRuleState.IptablesRuleState [[String]]
ruleToCommands flow policy acts =
    case policy of
      Conf.Accept -> (++) <$> policyCommands <*> actionsCommands
      _ -> (++) <$> actionsCommands <*> policyCommands
    where
        policyCommands =
            return [policyArguments flow $ matchAction policy]
        actionsCommands =
            fmap concat $ mapM (uncurry $ actionToCommands flow) acts

actionToCommands flow act tr = do
    let (table, chain) = matchFlow flow
        tr' = iptablesSimplify tr
    IptablesRuleState.setCurrentChain chain
    treeToCommands table (Data.Jump $ matchAction act) tr'

treeToCommands table act (CondTree.Leaf v) = do
    chain <- IptablesRuleState.getCurrentChain
    return $ [actionCommand table chain act $ Map.elems v]
treeToCommands table act (CondTree.NodeOr left right) =
    (++) <$> treeToCommands table act left <*>
        treeToCommands table act right
treeToCommands table act (CondTree.NodeAnd left right) =
    treeToCommands table act
        (CondTree.NodeNot
            (CondTree.NodeOr (CondTree.NodeNot left) (CondTree.NodeNot right)))
treeToCommands table act (CondTree.NodeNot node) = do
    name <- IptablesRuleState.nameChain "chain"
    cmds <- treeToCommands table (Data.Goto name) node
    chain <- IptablesRuleState.getCurrentChain
    IptablesRuleState.setCurrentChain name
    return $ (newChainCommands table name) ++
        cmds ++
        [actionCommand table chain act []]
treeToCommands _ _ CondTree.NodeFalse =
    return $ []
treeToCommands table act CondTree.NodeTrue = do
    chain <- IptablesRuleState.getCurrentChain
    return $ [actionCommand table chain act []]

actionCommand table chain act matches =
    (tableToArguments table) ++ (chainToArguments chain) ++
        (concatMap boolMatchToArguments matches) ++
            (actionToArguments act)
newChainCommand table chain =
    (tableToArguments table) ++ ["-N", chain]

boolMatchToArguments (True, match ) = matchToArguments match
boolMatchToArguments (False, match) = "!":(matchToArguments match)

newChainCommands table name =
    [newChainCommand table name]

networkToCommand MatchIPv4 = "iptables"
networkToCommand MatchIPv6 = "ip6tables"

chainToArguments chain = ["-A", chain]

policyArguments flow policy =
    let (table, chain) = matchFlow flow
    in (tableToArguments table) ++ ["-P", chain, targetToArgument policy]

-- TODO: handle negation for AnyValue
matchToArguments (Data.Source addr) = ["-s", show addr]
matchToArguments (Data.Destination addr) = ["-d", show addr]
matchToArguments (Data.Protocol Data.TCP) = ["-p", "tcp"]
matchToArguments (Data.Protocol Data.UDP) = ["-p", "udp"]
matchToArguments (Data.Protocol Data.ICMP) = ["-p", "icmp"]
matchToArguments (Data.Protocol Data.ICMPv6) = ["-p", "icmpv6"]
matchToArguments (Data.InInterface interface) = ["-i", interface]
matchToArguments (Data.OutInterface interface) = ["-o", interface]
matchToArguments (Data.SrcPort port) = ["--sport", show port]
matchToArguments (Data.DstPort port) = ["--dport", show port]
matchToArguments (Data.State sts)
  | not $ Set.null sts = ["-m", "conntrack", "--ctstate",
        List.intercalate "," $ map stateToArgument $ Set.toList sts]
  | otherwise = []
matchToArguments Data.AnyValue = []

targetToArgument (Data.SysTarget target) = builtinTargetToArgument target
targetToArgument (Data.UserTarget chain) = chain

stateToArgument Data.CtEstablished = "ESTABLISHED"
stateToArgument Data.CtRelated = "RELATED"

builtinTargetToArgument Data.Accept = "ACCEPT"
builtinTargetToArgument Data.Drop = "DROP"
builtinTargetToArgument Data.Reject = "REJECT"
builtinTargetToArgument Data.Log = "LOG"
builtinTargetToArgument Data.Return = "RETURN"

actionToArguments (Data.Goto chain) = ["-g", chain]
actionToArguments (Data.Jump target) = ["-j", targetToArgument target]

tableToArguments Data.Filter = ["-t", "filter"]
tableToArguments Data.Nat = ["-t", "nat"]
tableToArguments Data.Mangle = ["-t", "mangle"]
tableToArguments Data.Raw = ["-t", "raw"]

matchFlow :: Conf.Flow -> (Data.Table, String)
matchFlow Conf.Input = (Data.Filter, "INPUT")
matchFlow Conf.Output = (Data.Filter, "OUTPUT")
matchFlow Conf.Forward = (Data.Filter, "FORWARD")

matchAction :: Conf.Action -> Data.Target
matchAction Conf.Accept = Data.SysTarget Data.Accept
matchAction Conf.Drop = Data.SysTarget Data.Drop
matchAction Conf.Reject = Data.SysTarget Data.Reject

iptablesSimplifyOps = [
    growIptablesProps,
    growIptablesExtractNot,
    shrinkIptablesIntroduceNot,
    shrinkIptablesJoinMatches,
    shrinkIptablesProps,
    shrinkIptablesPrim,
    shrinkIptablesDistr,
    shrinkIptablesNegation
    ]

shrinkIptablesProps (CondTree.NodeNot (CondTree.NodeNot node)) = Just node
shrinkIptablesProps n = Nothing

shrinkIptablesJoinMatches (CondTree.NodeAnd
    (CondTree.Leaf left) (CondTree.Leaf right)) =
        let res = VS.intersection left right
        in case (VS.simpleValue res, VS.category res) of
             (_, VS.EmptySet) -> Just CondTree.NodeFalse
             (Just m, _) -> Just $ CondTree.Leaf m
             _ -> Nothing
shrinkIptablesJoinMatches (CondTree.NodeAnd
    n (CondTree.NodeAnd left right)) =
        (CondTree.NodeAnd <$>
            shrinkIptablesJoinMatches (CondTree.NodeAnd n left) <*> pure right) <|>
        (CondTree.NodeAnd <$>
            pure left <*> shrinkIptablesJoinMatches (CondTree.NodeAnd n right))
shrinkIptablesJoinMatches (CondTree.NodeAnd
    (CondTree.NodeAnd left right) n) =
        (CondTree.NodeAnd <$>
            shrinkIptablesJoinMatches (CondTree.NodeAnd left n) <*> pure right) <|>
        (CondTree.NodeAnd <$>
            pure left <*> shrinkIptablesJoinMatches (CondTree.NodeAnd right n))
shrinkIptablesJoinMatches (CondTree.NodeOr
    (CondTree.Leaf left) (CondTree.Leaf right)) =
        let res = VS.union left right
         in case VS.simpleValue res of
            Just m -> Just $ CondTree.Leaf m
            _ -> Nothing
shrinkIptablesJoinMatches (CondTree.NodeOr
    n (CondTree.NodeOr left right)) =
        (CondTree.NodeOr <$>
            shrinkIptablesJoinMatches (CondTree.NodeOr n left) <*> pure right) <|>
        (CondTree.NodeOr <$>
            pure left <*> shrinkIptablesJoinMatches (CondTree.NodeOr n right))
shrinkIptablesJoinMatches (CondTree.NodeOr
    (CondTree.NodeOr left right) n) =
        (CondTree.NodeOr <$>
            shrinkIptablesJoinMatches (CondTree.NodeOr left n) <*> pure right) <|>
        (CondTree.NodeOr <$>
            pure left <*> shrinkIptablesJoinMatches (CondTree.NodeOr right n))
shrinkIptablesJoinMatches _ = Nothing

shrinkIptablesIntroduceNot (CondTree.NodeNot (CondTree.Leaf v))
    | Map.size v <= 1 = Just $
        CondTree.Leaf $ invertMatches v
shrinkIptablesIntroduceNot (CondTree.NodeNot CondTree.NodeFalse) =
    Just CondTree.NodeTrue
shrinkIptablesIntroduceNot (CondTree.NodeNot CondTree.NodeTrue) =
    Just CondTree.NodeFalse
shrinkIptablesIntroduceNot _ = Nothing

growIptablesProps n@(CondTree.NodeAnd left right) = Just $
    CondTree.NodeNot
        (CondTree.NodeOr (CondTree.NodeNot left) (CondTree.NodeNot right))
growIptablesProps _ = Nothing

growIptablesExtractNot (CondTree.Leaf v)
    | Map.size v <= 1 = Just $
        CondTree.NodeNot $ CondTree.Leaf $ invertMatches v
growIptablesExtractNot _ = Nothing

shrinkIptablesPrim (CondTree.NodeAnd CondTree.NodeFalse _) =
    Just CondTree.NodeFalse
shrinkIptablesPrim (CondTree.NodeAnd CondTree.NodeTrue right) =
    Just right
shrinkIptablesPrim (CondTree.NodeOr CondTree.NodeTrue _) =
    Just CondTree.NodeTrue
shrinkIptablesPrim (CondTree.NodeOr CondTree.NodeFalse right) =
    Just right
shrinkIptablesPrim _ = Nothing

shrinkIptablesDistr (CondTree.NodeAnd base (CondTree.NodeOr left right)) =
    Just $ CondTree.NodeOr
            (CondTree.NodeAnd base left) (CondTree.NodeAnd base right)
shrinkIptablesDistr _ = Nothing

shrinkIptablesNegation (CondTree.NodeAnd (CondTree.NodeNot left) (CondTree.NodeNot right)) =
    Just $ CondTree.NodeNot $ CondTree.NodeOr left right
shrinkIptablesNegation _ =
    Nothing

invertMatches = Map.map (\(t, m) -> (not t, m))

-- TODO: match expressions complexity
treeMetric = CondTree.foldLeft (\r n -> r + nodeMetric n) 0
    where nodeMetric (CondTree.NodeAnd _ _) = 6
          nodeMetric (CondTree.NodeNot _) = 4
          nodeMetric (CondTree.NodeOr _ _) = 2
          nodeMetric (CondTree.Leaf _) = 1
          nodeMetric _ = 0
