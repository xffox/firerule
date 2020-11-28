{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TupleSections #-}
module Firerule.Conf where

import Data.Word (Word8, Word16, Word32, Word64)
import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.Maybe (fromMaybe)

import Firerule.IPv4
import Firerule.IPv6
import qualified Firerule.CondTree as CondTree
import qualified Firerule.ValueSet as VS
import qualified Firerule.BoolPair as BoolPair
import qualified Firerule.Port as Port
import qualified Firerule.Wrapped as Wrapped

-- There is no single ordering for firewall rules over multiple
-- layers, so ordering of rules should be explicit.

data Direction = Dst | Src | Any | None
    deriving (Eq, Show)

data ConnectionState = StateRelated | StateEstablished
    deriving (Eq, Ord, Show)

newtype Link = MACInterface MacParam
    deriving (Eq, Show)
data Network = IPv4Network IPv4Param |
               IPv6Network IPv6Param
   deriving (Eq, Show)
data Transport =
    TCPTransport TCPParam |
    UDPTransport UDPParam
   deriving (Eq, Show)

data MacParam = MacProto | MacAddr String
    deriving (Eq, Show)

data IPv4Param = IPv4Proto | IPv4Addr IPv4 | IPv4ICMP
    deriving (Eq, Show)

data IPv6Param = IPv6Proto | IPv6Addr IPv6 | IPv6ICMP
    deriving (Eq, Show)

data TCPParam = TCPProto | TCPPort Port.Port
    deriving (Eq, Show)

data UDPParam = UDPProto | UDPPort Port.Port
    deriving (Eq, Show)

data Flow = Input | Output | Forward
    deriving Show
data Action = Accept | Drop | Reject
    deriving Show

newtype Firewall = Firewall [Rule]
    deriving Show

data Layer = LinkLayer Link |
             NetworkLayer Network |
             TransportLayer Transport
    deriving (Eq, Show)

data DirectedLayer = DirectedLayer Direction (BoolPair.BoolPair Layer)
    deriving Show

data Rule = Rule Flow Action [(Action, RuleClause)]
    deriving Show

invertDirection Src = Dst
invertDirection Dst = Src
invertDirection Any = None
invertDirection None = Any

act :: Flow -> Action -> [(Action, RuleClause)] -> Rule
act = Rule

mac = MACInterface MacProto
macAddr addr = MACInterface (MacAddr addr)

udp = UDPTransport UDPProto
udpPort p = UDPTransport (UDPPort p)

tcp = TCPTransport TCPProto
tcpPort p = TCPTransport (TCPPort p)

ipv4 = IPv4Network IPv4Proto
ipv4Addr addr = IPv4Network (IPv4Addr addr)
icmp = IPv4Network IPv4ICMP

ipv6 = IPv6Network IPv6Proto
ipv6Addr addr = IPv6Network (IPv6Addr addr)
icmpv6 = IPv6Network IPv6ICMP

newtype RuleClause = RuleClause (CondTree.CondTree Condition)
    deriving Show

unclause (RuleClause tr) = tr

data Condition = LayerCondition DirectedLayer |
    StateCondition (BoolPair.BoolPair ConnectionState)
    deriving Show

class DirectedClauseable c where
    sel :: Direction -> BoolPair.BoolPair c -> RuleClause

instance DirectedClauseable Network where
    sel dir (neg, v) = RuleClause $ CondTree.Leaf $
        LayerCondition $ DirectedLayer dir (neg, NetworkLayer v)

instance DirectedClauseable Transport where
    sel dir (neg, v) = RuleClause $ CondTree.Leaf $
        LayerCondition $ DirectedLayer dir (neg, TransportLayer v)

instance DirectedClauseable Link where
    sel dir (neg, v) = RuleClause $ CondTree.Leaf $
        LayerCondition $ DirectedLayer dir (neg, LinkLayer v)

state = RuleClause . CondTree.Leaf . StateCondition

(<&>) :: RuleClause -> RuleClause -> RuleClause
(<&>) (RuleClause node1) (RuleClause node2) = RuleClause $ CondTree.NodeAnd node1 node2
(<|>) :: RuleClause -> RuleClause -> RuleClause
(<|>) (RuleClause node1) (RuleClause node2) = RuleClause $ CondTree.NodeOr node1 node2
notRule :: RuleClause -> RuleClause
notRule (RuleClause node) = RuleClause $ CondTree.NodeNot node

instance Wrapped.WrappedMergeable Layer where
    unwrap f (LinkLayer _) = f (extractLinkLayer, LinkLayer)
        where extractLinkLayer (LinkLayer v) = Just v
              extractLinkLayer _ = Nothing
    unwrap f (NetworkLayer _) = f (extractNetworkLayer, NetworkLayer)
        where extractNetworkLayer (NetworkLayer v) = Just v
              extractNetworkLayer _ = Nothing
    unwrap f (TransportLayer _) = f (extractTransportLayer, TransportLayer)
        where extractTransportLayer (TransportLayer v) = Just v
              extractTransportLayer _ = Nothing

instance VS.Mergeable Layer where
    intersection = Wrapped.intersectionWrapped
    union = Wrapped.unionWrapped
    emptySet = Nothing
    universeSet = Nothing

instance Wrapped.WrappedMergeable Link where
    unwrap f (MACInterface _) = f (extractMAC, MACInterface)
        where extractMAC (MACInterface v) = Just v

instance VS.Mergeable Link where
    intersection = Wrapped.intersectionWrapped
    union = Wrapped.unionWrapped
    emptySet = Nothing
    universeSet = Nothing

instance Wrapped.WrappedMergeable Network where
    unwrap f (IPv4Network _) = f (extractIPv4Network, IPv4Network)
        where extractIPv4Network (IPv4Network v) = Just v
              extractIPv4Network _ = Nothing
    unwrap f (IPv6Network _) = f (extractIPv6Network, IPv6Network)
        where extractIPv6Network (IPv6Network v) = Just v
              extractIPv4Network _ = Nothing

instance VS.Mergeable Network where
    intersection = Wrapped.intersectionWrapped
    union = Wrapped.unionWrapped
    emptySet = Nothing
    universeSet = Nothing

instance Wrapped.WrappedMergeable Transport where
    unwrap f (UDPTransport _) = f (extractUDPTransport, UDPTransport)
        where extractUDPTransport (UDPTransport v) = Just v
              extractUDPTransport _ = Nothing
    unwrap f (TCPTransport _) = f (extractTCPTransport, TCPTransport)
        where extractTCPTransport (TCPTransport v) = Just v
              extractTCPTransport _ = Nothing

instance VS.Mergeable Transport where
    intersection = Wrapped.intersectionWrapped
    union = Wrapped.unionWrapped
    emptySet = Nothing
    universeSet = Nothing

instance VS.Mergeable MacParam where
    intersection MacProto p = VS.fromValue p
    intersection p MacProto = VS.fromValue p
    intersection p@(MacAddr a1) (MacAddr a2)
      | a1 == a2 = VS.fromValue p
      | otherwise = VS.fromCategory VS.EmptySet
    union MacProto _ = VS.fromValue MacProto
    union _ MacProto = VS.fromValue MacProto
    union p@(MacAddr a1) (MacAddr a2) | a1 == a2 = VS.fromValue p
    union _ _ = VS.fromCategory VS.SomeSet
    emptySet = Nothing
    universeSet = Just MacProto

instance VS.Mergeable IPv4Param where
    intersection IPv4Proto p = VS.fromValue p
    intersection p IPv4Proto = VS.fromValue p
    intersection (IPv4Addr a1) (IPv4Addr a2) =
        Wrapped.mapSimpleValue IPv4Addr $ VS.intersection a1 a2
    intersection v1 v2
      | v1 == v2 = VS.fromValue v1
      | otherwise = VS.fromCategory VS.SomeSet
    union IPv4Proto _ = VS.fromValue IPv4Proto
    union _ IPv4Proto = VS.fromValue IPv4Proto
    union (IPv4Addr a1) (IPv4Addr a2) =
        Wrapped.mapSimpleValue IPv4Addr $ VS.union a1 a2
    union v1 v2
      | v1 == v2 = VS.fromValue v1
      | otherwise = VS.fromCategory VS.SomeSet
    emptySet = Nothing
    universeSet = Just IPv4Proto

instance VS.Mergeable IPv6Param where
    intersection IPv6Proto p = VS.fromValue p
    intersection p IPv6Proto = VS.fromValue p
    intersection p1@(IPv6Addr a1) p2@(IPv6Addr a2) =
        Wrapped.mapSimpleValue IPv6Addr $ VS.intersection a1 a2
    intersection v1 v2
      | v1 == v2 = VS.fromValue v1
      | otherwise = VS.fromCategory VS.SomeSet
    union IPv6Proto _ = VS.fromValue IPv6Proto
    union _ IPv6Proto = VS.fromValue IPv6Proto
    union (IPv6Addr a1) (IPv6Addr a2) =
        Wrapped.mapSimpleValue IPv6Addr $ VS.union a1 a2
    union v1 v2
      | v1 == v2 = VS.fromValue v1
      | otherwise = VS.fromCategory VS.SomeSet
    emptySet = Nothing
    universeSet = Just IPv6Proto

instance VS.Mergeable TCPParam where
    intersection TCPProto p = VS.fromValue p
    intersection p TCPProto = VS.fromValue p
    intersection p@(TCPPort t1) (TCPPort t2)
      | t1 == t2 = VS.fromValue p
      | otherwise = VS.fromCategory VS.SomeSet
    union TCPProto _ = VS.fromValue TCPProto
    union _ TCPProto = VS.fromValue TCPProto
    union p@(TCPPort t1) (TCPPort t2) | t1 == t2 = VS.fromValue p
    union v1 v2
      | v1 == v2 = VS.fromValue v1
      | otherwise = VS.fromCategory VS.SomeSet
    emptySet = Nothing
    universeSet = Just TCPProto

instance VS.Mergeable UDPParam where
    intersection UDPProto p = VS.fromValue p
    intersection p UDPProto = VS.fromValue p
    intersection p@(UDPPort t1) (UDPPort t2)
      | t1 == t2 = VS.fromValue p
      | otherwise = VS.fromCategory VS.SomeSet
    union UDPProto _ = VS.fromValue UDPProto
    union _ UDPProto = VS.fromValue UDPProto
    union p@(UDPPort t1) (UDPPort t2) | t1 == t2 = VS.fromValue p
    union v1 v2
      | v1 == v2 = VS.fromValue v1
      | otherwise = VS.fromCategory VS.SomeSet
    emptySet = Nothing
    universeSet = Just UDPProto
