{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
module Firerule.Iptables.IptablesBuilder where

import Data.Word (Word16)
import qualified Data.Map as Map
import qualified Data.Set as Set
import qualified Data.List as List
import qualified Control.Monad as Monad
import qualified Data.Maybe as Maybe

import qualified Firerule.IPv4 as IPv4
import qualified Firerule.ValueSet as VS
import qualified Firerule.Conf as Conf
import qualified Firerule.Analyzer as Analyzer
import qualified Firerule.CondTree as CondTree
import qualified Firerule.Iptables.IptablesRuleState as IptablesRuleState
import qualified Firerule.Iptables.IptablesData as Data

buildCommands :: Conf.Firewall -> [(String, [String])]
buildCommands = firewallToCommands

iptablesSimplify =
    Analyzer.simplify iptablesSimplifyOps compareIptables

type MatchExpr = Map.Map MatchKey (Data.MatchValue, Bool)

iptablesCondTree :: CondTree.CondTree Conf.Condition ->
    (CondTree.CondTree MatchExpr, CondTree.CondTree MatchExpr)
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
        tr = fmap (\v -> Map.singleton (matchValueKey v) (v, True))
     in (tr subtree1, tr subtree2)
    where
        conditionToMatch (Conf.LayerCondition v) = layerToMatch v
        conditionToMatch (Conf.StateCondition v) = stateToMatch v
        layerToMatch (Conf.DirectedLayer dir
            (Conf.LinkLayer l)) = linkLayerToMatch dir l
        layerToMatch (Conf.DirectedLayer dir
            (Conf.NetworkLayer l)) = netLayerToMatch dir l
        layerToMatch (Conf.DirectedLayer dir
            (Conf.TransportLayer l)) = transportLayerToMatch dir l
        linkLayerToMatch dir (Conf.MACInterface p) =
            macParamToMatch dir p
        netLayerToMatch dir (Conf.IPv4Network p) =
            ipv4ParamToMatch dir p
        netLayerToMatch dir (Conf.IPv6Network p) =
            ipv6ParamToMatch dir p
        transportLayerToMatch dir (Conf.TCPTransport p) =
            tcpParamToMatch dir p
        transportLayerToMatch dir (Conf.UDPTransport p) =
            udpParamToMatch dir p
        macParamToMatch _ Conf.MacProto =
            let m = CondTree.NodeTrue
             in (m, m)
        macParamToMatch Conf.Src (Conf.MacAddr a) =
            let m = CondTree.Leaf (Data.InInterface a)
             in (m, m)
        macParamToMatch Conf.Dst (Conf.MacAddr a) =
            let m = CondTree.Leaf (Data.OutInterface a)
             in (m, m)
        macParamToMatch Conf.Any (Conf.MacAddr a) =
            let m = CondTree.NodeOr
                        (CondTree.Leaf (Data.OutInterface a))
                        (CondTree.Leaf (Data.InInterface a))
             in (m, m)
        ipv4ParamToMatch _ Conf.IPv4Proto =
            (CondTree.NodeTrue, CondTree.NodeFalse)
        ipv4ParamToMatch Conf.Src (Conf.IPv4Addr a) =
            (CondTree.Leaf (Data.Source $ Data.IPv4 a),
                CondTree.NodeFalse)
        ipv4ParamToMatch Conf.Dst (Conf.IPv4Addr a) =
            (CondTree.Leaf (Data.Destination $ Data.IPv4 a),
                CondTree.NodeFalse)
        ipv4ParamToMatch Conf.Any (Conf.IPv4Addr a) =
            (CondTree.NodeOr
                (CondTree.Leaf (Data.Destination $ Data.IPv4 a))
                (CondTree.Leaf (Data.Source $ Data.IPv4 a)),
                CondTree.NodeFalse)
        ipv4ParamToMatch _ Conf.IPv4ICMP =
            (CondTree.Leaf (Data.Protocol Data.ICMP), CondTree.NodeFalse)
        ipv6ParamToMatch _ Conf.IPv6Proto =
            (CondTree.NodeFalse, CondTree.NodeTrue)
        ipv6ParamToMatch Conf.Src (Conf.IPv6Addr a) =
            (CondTree.NodeFalse,
                CondTree.Leaf (Data.Source $ Data.IPv6 a))
        ipv6ParamToMatch Conf.Dst (Conf.IPv6Addr a) =
            (CondTree.NodeFalse,
                CondTree.Leaf (Data.Destination $ Data.IPv6 a))
        ipv6ParamToMatch Conf.Any (Conf.IPv6Addr a) =
            (CondTree.NodeFalse,
                CondTree.NodeOr
                    (CondTree.Leaf (Data.Destination $ Data.IPv6 a))
                    (CondTree.Leaf (Data.Source $ Data.IPv6 a)))
        ipv6ParamToMatch _ Conf.IPv6ICMP =
            (CondTree.NodeFalse, CondTree.Leaf (Data.Protocol Data.ICMPv6))
        tcpParamToMatch _ Conf.TCPProto =
            let m = CondTree.Leaf (Data.Protocol Data.TCP)
             in (m, m)
        tcpParamToMatch Conf.Src (Conf.TCPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (Data.Protocol Data.TCP))
                        (CondTree.Leaf (Data.SrcPort p))
             in (m, m)
        tcpParamToMatch Conf.Dst (Conf.TCPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (Data.Protocol Data.TCP))
                        (CondTree.Leaf (Data.DstPort p))
             in (m, m)
        tcpParamToMatch Conf.Any (Conf.TCPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (Data.Protocol Data.TCP))
                        (CondTree.NodeOr
                            (CondTree.Leaf (Data.SrcPort p))
                            (CondTree.Leaf (Data.DstPort p))
                            )
             in (m, m)
        udpParamToMatch _ Conf.UDPProto =
            let m = CondTree.Leaf (Data.Protocol Data.UDP)
             in (m, m)
        udpParamToMatch Conf.Src (Conf.UDPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (Data.Protocol Data.UDP))
                        (CondTree.Leaf (Data.SrcPort p))
             in (m, m)
        udpParamToMatch Conf.Dst (Conf.UDPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (Data.Protocol Data.UDP))
                        (CondTree.Leaf (Data.DstPort p))
             in (m, m)
        udpParamToMatch Conf.Any (Conf.UDPPort p) =
            let m = CondTree.NodeAnd
                        (CondTree.Leaf (Data.Protocol Data.UDP))
                        (CondTree.NodeOr
                            (CondTree.Leaf (Data.SrcPort p))
                            (CondTree.Leaf (Data.DstPort p))
                            )
             in (m, m)
        stateToMatch Conf.StateRelated =
            let m = CondTree.Leaf (Data.State $
                    Set.singleton Data.CtRelated)
             in (m, m)
        stateToMatch Conf.StateEstablished =
            let m = CondTree.Leaf (Data.State $
                    Set.singleton Data.CtEstablished)
             in (m, m)

data MatchKey =
    MatchSource
    | MatchDestination
    | MatchProtocol
    | MatchInInterface
    | MatchOutInterface
    | MatchSrcPort
    | MatchDstPort
    | MatchCtState
    deriving (Eq, Ord, Show)

data NetworkMatch = MatchIPv4 | MatchIPv6
    deriving (Eq, Ord, Enum, Bounded)

matchValueKey (Data.Source _) = MatchSource
matchValueKey (Data.Destination _) = MatchDestination
matchValueKey (Data.Protocol _) = MatchProtocol
matchValueKey (Data.InInterface _) = MatchInInterface
matchValueKey (Data.OutInterface _) = MatchOutInterface
matchValueKey (Data.SrcPort _) = MatchSrcPort
matchValueKey (Data.DstPort _) = MatchDstPort
matchValueKey (Data.State _) = MatchCtState

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
    [(Conf.Action, CondTree.CondTree MatchExpr)] ->
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

swapIf (a, b) True = (b, a)
swapIf p _ = p

actionCommand table chain act matches =
    (tableToArguments table) ++ (chainToArguments chain) ++
        (concatMap boolMatchToArguments matches) ++
            (actionToArguments act)
newChainCommand table chain =
    (tableToArguments table) ++ ["-N", chain]

boolMatchToArguments (match, True) = matchToArguments match
boolMatchToArguments (match, False) = "!":(matchToArguments match)

newChainCommands table name =
    [newChainCommand table name]

networkToCommand MatchIPv4 = "iptables"
networkToCommand MatchIPv6 = "ip6tables"

chainToArguments chain = ["-A", chain]

policyArguments flow policy =
    let (table, chain) = matchFlow flow
    in (tableToArguments table) ++ ["-P", chain, targetToArgument policy]

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
        List.intercalate "," $ map stateToArgument $ Set.toList $ sts]
  | otherwise = []

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

instance VS.Mergeable MatchExpr where
    mergeIntersect left right =
        case Monad.foldM step (Just left) (Map.assocs right) of
            Left _ -> []
            Right Nothing -> [left, right]
            Right (Just r) -> [r]
        where step Nothing _ = Right $ Nothing
              step (Just r) (k, v) =
                  case Map.lookup k r of
                      Just rv -> case VS.mergeIntersect v rv of
                          [] -> Left ()
                          [v'] -> Right $ Just $ Map.insert k v' r
                          _ -> Right $ Nothing
                      Nothing -> Right $ Just $ Map.insert k v r
    mergeJoin left right =
        let keys = Set.toList $ Set.fromList $ Map.keys left ++ Map.keys right
            leftVals = map (fmap (:[]) . (flip Map.lookup $ left)) keys
            rightVals = map (fmap (:[]). (flip Map.lookup $ right)) keys
         in case keys of
              [k] -> fmap (Map.singleton k) $
                  VS.mergeJoin (head $ Maybe.fromJust $ head $ leftVals) (head $ Maybe.fromJust $ head rightVals)
              _ -> let res = zipWith valueUnion leftVals rightVals
                    in if res == leftVals || res == rightVals
                          then Just $ Map.fromList $ map (\(k, v) -> (k, head $ Maybe.fromJust v)) $
                              filter ((/=) Nothing . snd) $ zip keys res
                          else Nothing
        where valueUnion Nothing _ = Nothing
              valueUnion _ Nothing = Nothing
              valueUnion (Just [l]) (Just [r]) =
                  case VS.mergeJoin l r of
                    Nothing -> Just [l, r]
                    Just v -> Just [v]

iptablesSimplifyOps = [
    growIptablesProps,
    growIptablesExtractNot,
    shrinkIptablesIntroduceNot,
    shrinkIptablesJoinMatches,
    shrinkIptablesProps,
    shrinkIptablesPrim,
    shrinkIptablesDistr,
    swapIptablesNodes
    ]

shrinkIptablesProps (CondTree.NodeNot (CondTree.NodeNot node)) = Just node
shrinkIptablesProps n = Nothing

shrinkIptablesJoinMatches (CondTree.NodeAnd
    (CondTree.Leaf left) (CondTree.Leaf right)) =
        case VS.mergeIntersect left right of
            [] -> Just $ CondTree.NodeFalse
            [m] -> Just $ CondTree.Leaf m
            _ -> Nothing
shrinkIptablesJoinMatches (CondTree.NodeOr
    (CondTree.Leaf left) (CondTree.Leaf right)) =
        case VS.mergeJoin left right of
            Just m -> Just $ CondTree.Leaf m
            _ -> Nothing
shrinkIptablesJoinMatches _ = Nothing

shrinkIptablesIntroduceNot (CondTree.NodeNot (CondTree.Leaf v))
    | Map.size v <= 1 = Just $
        CondTree.Leaf $ invertMatches v
shrinkIptablesIntroduceNot (CondTree.NodeNot CondTree.NodeFalse) =
    Just $ CondTree.NodeTrue
shrinkIptablesIntroduceNot (CondTree.NodeNot CondTree.NodeTrue) =
    Just $ CondTree.NodeFalse
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
shrinkIptablesPrim (CondTree.NodeAnd _ CondTree.NodeFalse) =
    Just CondTree.NodeFalse
shrinkIptablesPrim (CondTree.NodeAnd CondTree.NodeTrue right) =
    Just right
shrinkIptablesPrim (CondTree.NodeAnd left CondTree.NodeTrue) =
    Just left
shrinkIptablesPrim (CondTree.NodeOr CondTree.NodeTrue _) =
    Just CondTree.NodeTrue
shrinkIptablesPrim (CondTree.NodeOr _ CondTree.NodeTrue) =
    Just CondTree.NodeTrue
shrinkIptablesPrim (CondTree.NodeOr CondTree.NodeFalse right) =
    Just right
shrinkIptablesPrim (CondTree.NodeOr left CondTree.NodeFalse) =
    Just left
shrinkIptablesPrim _ = Nothing

shrinkIptablesDistr (CondTree.NodeAnd base (CondTree.NodeOr left right)) =
    Just $ CondTree.NodeOr
            (CondTree.NodeAnd base left) (CondTree.NodeAnd base right)
shrinkIptablesDistr (CondTree.NodeAnd (CondTree.NodeOr left right) base) =
    Just $ CondTree.NodeOr
            (CondTree.NodeAnd base left) (CondTree.NodeAnd base right)
shrinkIptablesDistr _ = Nothing

swapIptablesNodes (CondTree.NodeOr left right) =
    Just $ CondTree.NodeOr right left
swapIptablesNodes (CondTree.NodeAnd left right) =
    Just $ CondTree.NodeAnd right left
swapIptablesNodes _ = Nothing

compareIptables left right = compare (treeMetric left) (treeMetric right)

invertMatches = Map.map (\(m, t) -> (m, not t))

treeMetric = CondTree.foldLeft (\r n -> r + nodeMetric n) 0
    where nodeMetric (CondTree.NodeAnd _ _) = 5
          nodeMetric (CondTree.NodeNot _) = 4
          nodeMetric (CondTree.NodeOr _ _) = 2
          nodeMetric (CondTree.Leaf _) = 1
          nodeMetric _ = 0
