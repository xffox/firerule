module Firerule.Format.PrefixTree(PrefixTree, findPrefix, insertPrefix,
    buildPrefixTree, appendPrefix) where

import qualified Data.Map as Map
import qualified Data.Maybe as Maybe
import qualified Control.Monad.State.Strict as State

data PrefixTree k v =
    PrefixNode (Maybe v) (Map.Map k (PrefixTree k v))

emptyPrefixTree = PrefixNode Nothing Map.empty

findPrefix [] (PrefixNode r _) = r
findPrefix (v:vs) (PrefixNode _ m) =
    case Map.lookup v m of
      Just n -> findPrefix vs n
      _ -> Nothing

insertPrefix [] r (PrefixNode _ m) = PrefixNode (Just r) m
insertPrefix (v:vs) r (PrefixNode pr m) =
    let n = Maybe.fromMaybe emptyPrefixTree $ Map.lookup v m
     in PrefixNode pr (Map.insert v (insertPrefix vs r n) m)

data PrefixTreeBuilder k v a =
    PrefixTreeBuilder (State.State (PrefixTree k v) a)

instance Functor (PrefixTreeBuilder k v) where
    fmap f (PrefixTreeBuilder m) = PrefixTreeBuilder $ fmap f m

instance Applicative (PrefixTreeBuilder k v) where
    pure v = PrefixTreeBuilder $ pure v
    (<*>) (PrefixTreeBuilder f) (PrefixTreeBuilder v) =
        PrefixTreeBuilder $ f <*> v

instance Monad (PrefixTreeBuilder k v) where
    (>>=) (PrefixTreeBuilder m) f = PrefixTreeBuilder $ do
        (PrefixTreeBuilder m') <- fmap f m
        m'

buildPrefixTree (PrefixTreeBuilder b) = State.execState b emptyPrefixTree

appendPrefix ns value = PrefixTreeBuilder $ do
    State.modify (\tr -> insertPrefix ns value tr)
    return ()
