module Firerule.Conf where

import Data.Word (Word8, Word16, Word32, Word64)
import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.Maybe (fromMaybe)

import Firerule.IPv4
import Firerule.IPv6
import qualified Firerule.CondTree as CondTree
import qualified Firerule.ValueSet as VS
import qualified Firerule.Port as Port

-- There is no single ordering for firewall rules over multiple
-- layers, so ordering of rules should be explicit.

data Direction = Dst | Src | Any
    deriving (Eq, Show)

data ConnectionState = StateRelated | StateEstablished
    deriving (Eq, Ord, Show)

data Link = MACInterface MacParam
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

data Firewall = Firewall [Rule]
    deriving Show

data Layer = LinkLayer Link |
             NetworkLayer Network |
             TransportLayer Transport
    deriving (Eq, Show)

data DirectedLayer = DirectedLayer Direction Layer
    deriving Show

data Rule = Rule Flow Action [(Action, RuleClause)]
    deriving Show

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
    StateCondition ConnectionState
    deriving Show

class DirectedClauseable c where
    sel :: Direction -> c -> RuleClause

instance DirectedClauseable Network where
    sel dir v = RuleClause $ CondTree.Leaf $
        LayerCondition $ DirectedLayer dir $ NetworkLayer $ v

instance DirectedClauseable Transport where
    sel dir v = RuleClause $ CondTree.Leaf $
        LayerCondition $ DirectedLayer dir $ TransportLayer $ v

instance DirectedClauseable Link where
    sel dir v = RuleClause $ CondTree.Leaf $
        LayerCondition $ DirectedLayer dir $ LinkLayer $ v

state = RuleClause . CondTree.Leaf . StateCondition

(<&>) :: RuleClause -> RuleClause -> RuleClause
(<&>) (RuleClause node1) (RuleClause node2) = RuleClause $ CondTree.NodeAnd node1 node2
(<|>) :: RuleClause -> RuleClause -> RuleClause
(<|>) (RuleClause node1) (RuleClause node2) = RuleClause $ CondTree.NodeOr node1 node2
notRule :: RuleClause -> RuleClause
notRule (RuleClause node) = RuleClause $ CondTree.NodeNot node

instance VS.Mergeable Layer where
    mergeIntersect (LinkLayer l1) (LinkLayer l2) = LinkLayer <$> VS.mergeIntersect l1 l2
    mergeIntersect (NetworkLayer n1) (NetworkLayer n2) = NetworkLayer <$> VS.mergeIntersect n1 n2
    mergeIntersect (TransportLayer t1) (TransportLayer t2) = TransportLayer <$> VS.mergeIntersect t1 t2
    mergeIntersect l1 l2 = [l1, l2]
    mergeJoin (LinkLayer l1) (LinkLayer l2) = LinkLayer <$> VS.mergeJoin l1 l2
    mergeJoin (NetworkLayer n1) (NetworkLayer n2) = NetworkLayer <$> VS.mergeJoin n1 n2
    mergeJoin (TransportLayer t1) (TransportLayer t2) = TransportLayer <$> VS.mergeJoin t1 t2
    mergeJoin l1 l2 = Nothing

instance VS.Mergeable Link where
    mergeIntersect l1@(MACInterface v1) l2@(MACInterface v2) =
        fmap MACInterface $ VS.mergeIntersect v1 v2
    mergeJoin l1@(MACInterface v1) l2@(MACInterface v2) =
        fmap MACInterface $ VS.mergeJoin v1 v2

instance VS.Mergeable Network where
    mergeIntersect n1@(IPv4Network nv1) n2@(IPv4Network nv2) =
        fmap IPv4Network $ VS.mergeIntersect nv1 nv2
    mergeIntersect _ _ = []
    mergeJoin n1@(IPv4Network nv1) n2@(IPv4Network nv2) =
        fmap IPv4Network $ VS.mergeJoin nv1 nv2
    mergeJoin _ _ = Nothing

instance VS.Mergeable Transport where
    mergeIntersect t1@(UDPTransport param1) t2@(UDPTransport param2) =
        fmap UDPTransport $ VS.mergeIntersect param1 param2
    mergeIntersect t1@(TCPTransport tv1) t2@(TCPTransport tv2) =
        fmap TCPTransport $ VS.mergeIntersect tv1 tv2
    mergeIntersect _ _ = []
    mergeJoin (UDPTransport p1) (UDPTransport p2) =
        fmap UDPTransport $ VS.mergeJoin p1 p2
    mergeJoin (TCPTransport p1) (TCPTransport p2) =
        fmap TCPTransport $ VS.mergeJoin p1 p2
    mergeJoin t1 t2 = Nothing

instance VS.Mergeable MacParam where
    mergeIntersect MacProto p = [p]
    mergeIntersect p MacProto = [p]
    mergeIntersect p@(MacAddr a1) (MacAddr a2)
        | a1 == a2 = [p]
        | otherwise = []
    mergeJoin MacProto _ = Just MacProto
    mergeJoin _ MacProto = Just MacProto
    mergeJoin p@(MacAddr a1) (MacAddr a2) | a1 == a2 = Just p
    mergeJoin _ _ = Nothing

instance VS.Mergeable IPv4Param where
    mergeIntersect IPv4Proto p = [p]
    mergeIntersect p IPv4Proto = [p]
    mergeIntersect (IPv4Addr a1) (IPv4Addr a2) =
        fmap IPv4Addr $ VS.mergeIntersect a1 a2
    mergeIntersect p1 p2 = [p1, p2]
    mergeJoin IPv4Proto _ = Just IPv4Proto
    mergeJoin _ IPv4Proto = Just IPv4Proto
    mergeJoin (IPv4Addr a1) (IPv4Addr a2) =
        fmap IPv4Addr $ VS.mergeJoin a1 a2
    mergeJoin _ _ = Nothing

instance VS.Mergeable IPv6Param where
    mergeIntersect IPv6Proto p = [p]
    mergeIntersect p IPv6Proto = [p]
    mergeIntersect p1@(IPv6Addr a1) p2@(IPv6Addr a2) =
        fmap IPv6Addr $ VS.mergeIntersect a1 a2
    mergeIntersect p1 p2 = [p1, p2]
    mergeJoin IPv6Proto _ = Just IPv6Proto
    mergeJoin _ IPv6Proto = Just IPv6Proto
    mergeJoin (IPv6Addr a1) (IPv6Addr a2) =
        fmap IPv6Addr $ VS.mergeJoin a1 a2
    mergeJoin _ _ = Nothing

instance VS.Mergeable TCPParam where
    mergeIntersect TCPProto p = [p]
    mergeIntersect p TCPProto = [p]
    mergeIntersect p@(TCPPort t1) (TCPPort t2)
        | t1 == t2 = [p]
        | otherwise = []
    mergeJoin TCPProto _ = Just TCPProto
    mergeJoin _ TCPProto = Just TCPProto
    mergeJoin p@(TCPPort t1) (TCPPort t2) | t1 == t2 = Just p
    mergeJoin _ _ = Nothing

instance VS.Mergeable UDPParam where
    mergeIntersect UDPProto p = [p]
    mergeIntersect p UDPProto = [p]
    mergeIntersect p@(UDPPort t1) (UDPPort t2)
        | t1 == t2 = [p]
        | otherwise = []
    mergeJoin UDPProto _ = Just UDPProto
    mergeJoin _ UDPProto = Just UDPProto
    mergeJoin p@(UDPPort t1) (UDPPort t2) | t1 == t2 = Just p
    mergeJoin _ _ = Nothing
