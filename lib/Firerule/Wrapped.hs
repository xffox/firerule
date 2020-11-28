{-# LANGUAGE RankNTypes #-}
module Firerule.Wrapped(WrappedMergeable(..),
    intersectionWrapped, unionWrapped, apply, mapSimpleValue) where

import qualified Data.Maybe as Maybe

import qualified Firerule.ValueSet as VS

class WrappedMergeable w where
    unwrap :: (forall m. VS.Mergeable m => (w -> Maybe m, m -> w) -> r) ->
        w -> r

-- TODO: maybe accept default category
intersectionWrapped :: (VS.Mergeable w, WrappedMergeable w) =>
    w -> w -> VS.ValueSet w
intersectionWrapped v1 v2 =
    unwrap (\(extract, build) ->
        mapSimpleValue build $
            Maybe.fromMaybe (VS.fromCategory VS.EmptySet) $ do
                v1' <- extract v1
                v2' <- extract v2
                return $ VS.intersection v1' v2') v1
-- TODO: maybe accept default category
unionWrapped :: (VS.Mergeable w, WrappedMergeable w) =>
    w -> w -> VS.ValueSet w
unionWrapped v1 v2 =
    unwrap (\(extract, build) ->
        mapSimpleValue build $
            Maybe.fromMaybe (VS.fromCategory VS.SomeSet) $ do
                v1' <- extract v1
                v2' <- extract v2
                return $ VS.union v1' v2') v1

apply :: WrappedMergeable w => (forall m. VS.Mergeable m => m -> r) -> w -> r
apply f val = unwrap (\(extract, _) -> f $ Maybe.fromJust $ extract val) val

mapSimpleValue f val =
    case VS.simpleValue val of
      Just v -> VS.fromValue $ f v
      Nothing -> VS.fromCategory $ VS.category val
