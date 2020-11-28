{-# LANGUAGE FlexibleInstances #-}
module Firerule.Iptables.MatchExpr(MatchKey(..), MatchExpr(..)) where

import qualified Control.Monad as Monad
import qualified Data.Map as Map
import qualified Data.Set as Set
import qualified Data.List as List
import qualified Data.Maybe as Maybe

import qualified Firerule.ValueSet as VS
import qualified Firerule.Iptables.IptablesData as Data
import qualified Firerule.Wrapped as Wrapped
import qualified Firerule.BoolPair as BoolPair

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

type MatchExpr = Map.Map MatchKey (BoolPair.BoolPair Data.MatchValue)

instance VS.Mergeable MatchExpr where
    intersection left right =
        case Monad.foldM step (Just left) (Map.assocs right) of
            Left _ -> VS.fromCategory VS.EmptySet
            Right Nothing -> VS.fromCategory VS.SomeSet
            Right (Just r) -> VS.fromValue r
        where step Nothing _ = Right Nothing
              step (Just r) (k, v) =
                  case Map.lookup k r of
                      Just rv ->
                          let intval = VS.intersection v rv
                           in case (VS.simpleValue intval, VS.category intval) of
                                (_, VS.EmptySet) -> Left ()
                                (Just sv, _) -> Right $ Just $ Map.insert k sv r
                                _ -> Right Nothing
                      Nothing -> Right $ Just $ Map.insert k v r
    union left right
      | Map.size left > Map.size right = VS.union right left
      | otherwise =
          let res = fmap simplifyMatchExpr $
                  (Monad.foldM step (Map.empty, 0) (Map.toList left) >>= fromJoined)
           in case res of
                Just v -> VS.fromValue v
                Nothing -> VS.fromCategory VS.SomeSet
            where step (res, joined) (k, v) =
                    case Map.lookup k right of
                      (Just v') | v' == v -> Just (Map.insert k v res, joined)
                      (Just v') | joined == 0 ->
                          fmap (\r -> (Map.insert k r res,joined+1))
                            (VS.simpleValue $ VS.union v' v)
                      _ -> fail ""
                  fromJoined (res, 0) = return res
                  fromJoined (res, _)
                    | Map.keys left == Map.keys right = return res
                    | otherwise = fail ""
    emptySet = Nothing
    universeSet = Just Map.empty

simplifyMatchExpr values =
        Maybe.fromJust $ Map.traverseMaybeWithKey skipAnyValue values
    where skipAnyValue _ (True, Data.AnyValue) = Just Nothing
          skipAnyValue _ v = Just $ Just v
