{-# LANGUAGE FlexibleContexts #-}
module Firerule.Format.RuleParser(parseFirewall,
    Rule(..), Jump(..), Firewall(..), Condition(..)) where

import qualified Control.Monad as M
import qualified Data.Char as Char
import qualified Data.Maybe as Maybe
import qualified Data.List as List
import qualified Data.Set as Set
import qualified Data.Map as Map
import qualified Text.Parsec as Parsec
import qualified Text.Printf as Printf
import qualified Data.Functor.Identity as Identity
import qualified Control.Monad as Monad
import qualified Control.Monad.State as State
import qualified Control.Monad.Trans.Except as Except
import qualified Control.Monad.Trans.Class as Trans
import Text.Parsec((<|>))

import qualified Firerule.CondTree as CT
import qualified Firerule.BoolPair as BoolPair
import qualified Firerule.IPv4 as IPv4
import qualified Firerule.IPv6 as IPv6

newtype Condition = Condition [BoolPair.BoolPair String]
    deriving (Eq, Show)
data Rule = Rule String [Jump]
    deriving (Eq, Show)
data Jump = DefaultJump String | Jump String (CT.CondTree Condition)
    deriving (Eq, Show)
newtype Firewall = Firewall [Rule]
    deriving (Eq, Show)

data Argument = Argument String | TreeArgument (CT.CondTree [Argument])

parseFirewall :: String -> Either String Firewall
parseFirewall inp = case Parsec.parse rules "inp" inp of
                      Right (Firewall rules) ->
                          Firewall <$> substituteRules rules
                      Left v -> Left $ "parse failed: " ++ show v

rules = do
    res <- fmap Firewall $ Parsec.endBy1 rule (Parsec.char ';')
    Parsec.spaces
    Parsec.eof
    return res

rule = Parsec.try $ do
    Parsec.spaces
    f <- flow
    Parsec.spaces
    Parsec.char ':'
    Parsec.spaces
    js <- jumps
    return $ Rule f js

jumps = Parsec.sepBy1 jump (Parsec.char ',')

flow = argument

action = argument

jump = Parsec.try $ do
    Parsec.spaces
    act <- action
    Parsec.spaces
    Parsec.choice [
        do
            Parsec.char '%'
            Parsec.spaces
            c <- jumpCondition
            return $ Jump act c,
        return $ DefaultJump act
        ]

jumpCondition = do
    cl <- clause
    case mapM step (expandConditionTree cl) of
      Right ct -> return ct
      Left er -> fail er
    where step [] = fail "empty rules"
          step rs = return $ Condition rs

clause = orExpr

andExpr = clauseAtom `Parsec.chainl1` connectAnd

orExpr = andExpr `Parsec.chainl1` connectOr

clauseAtom = do
   c <- condition;
   case c of
     [TreeArgument t] -> return t
     _ -> return $ CT.Leaf c

notClause =
    Parsec.try $ do
        Parsec.spaces
        Parsec.char '!'
        Parsec.spaces
        CT.NodeNot . CT.Leaf . (:[]) <$> conditionAtom

braceClause =
    Parsec.try $ do
        Parsec.spaces
        Parsec.char '('
        Parsec.spaces
        c <- clause
        Parsec.spaces
        Parsec.char ')'
        Parsec.spaces
        return c

connectOr =
    Parsec.try $ do
        Parsec.spaces
        Parsec.char '|'
        Parsec.spaces
        return CT.NodeOr

connectAnd =
    Parsec.try $ do
        Parsec.spaces
        Parsec.char '&'
        Parsec.spaces
        return CT.NodeAnd

condition = do
    Parsec.spaces
    Parsec.many1 conditionAtom

conditionAtom = (fmap Argument argument) <|>
    (fmap TreeArgument braceClause) <|>
        (fmap TreeArgument notClause)

-- TODO: check `noneOf` values
argument = Parsec.try $ do
    Parsec.spaces
    v <-
        (do
            Parsec.char '\''
            v <- Parsec.many1 (Parsec.noneOf ['\''])
            Parsec.char '\''
            return v
        ) <|>
            (Parsec.many1 (Parsec.noneOf ['!', '\'', '|', '&', ',', ')', '(', ':', ';', ' ', '\n', '\t']))
    Parsec.spaces
    return v

expandConditionTree = expandConditionTree'
    where
        expandConditionTree' (CT.Leaf args) =
            expandConditionArgs (CT.Leaf []) True (reverse args)
        expandConditionTree' CT.NodeTrue = CT.NodeTrue
        expandConditionTree' CT.NodeFalse = CT.NodeFalse
        expandConditionTree' (CT.NodeNot n) =
            CT.NodeNot $ expandConditionTree' n
        expandConditionTree' (CT.NodeOr left right) =
            CT.NodeOr (expandConditionTree' left)
                (expandConditionTree' right)
        expandConditionTree' (CT.NodeAnd left right) =
            CT.NodeAnd (expandConditionTree' left)
                (expandConditionTree' right)
        expandConditionArgsTree ptr _ CT.NodeTrue = ptr
        expandConditionArgsTree ptr _ CT.NodeFalse = ptr -- is this right
        expandConditionArgsTree ptr cnd (CT.NodeNot n) =
            expandConditionArgsTree ptr (not cnd) n
        expandConditionArgsTree ptr True (CT.NodeOr left right) =
            CT.NodeOr (expandConditionArgsTree ptr True left)
                (expandConditionArgsTree ptr True right)
        expandConditionArgsTree ptr False (CT.NodeOr left right) =
            CT.NodeAnd (expandConditionArgsTree ptr False left)
                (expandConditionArgsTree ptr False right)
        expandConditionArgsTree ptr True (CT.NodeAnd left right) =
            CT.NodeAnd (expandConditionArgsTree ptr True left)
                (expandConditionArgsTree ptr True right)
        expandConditionArgsTree ptr False (CT.NodeAnd left right) =
            CT.NodeOr (expandConditionArgsTree ptr False left)
                (expandConditionArgsTree ptr False right)
        expandConditionArgsTree ptr cnd (CT.Leaf args) =
            expandConditionArgs ptr cnd (reverse args)
        expandConditionArgs n cnd [] = n
        expandConditionArgs n cnd (Argument s:args) =
            expandConditionArgs (fmap ((cnd, s):) n) cnd args
        expandConditionArgs n cnd (TreeArgument t:args) =
            expandConditionArgs (expandConditionArgsTree n cnd t) cnd args

substituteRules :: [Rule] -> Either String [Rule]
substituteRules = Monad.mapM substituteJumps

substituteJumps :: Rule -> Either String Rule
substituteJumps (Rule name jumps) = Rule name <$>
    fst (flip State.runState Map.empty $ Except.runExceptT $
            Monad.mapM substituteJump jumps)
        where substituteJump jump@(DefaultJump name) = do
                  Trans.lift $ State.modify (Map.insert name CT.NodeTrue)
                  return jump
              substituteJump (Jump name tree) =
                  Jump name <$>
                      CT.restructTreeM (substituteNode Set.empty) tree
              substituteNode seen n@(CT.Leaf (Condition [(True, v)])) = do
                  processedJumps <- Trans.lift State.get
                  case (Map.lookup v processedJumps, Map.lookup v jumpTrees) of
                     (Just tree, _) ->
                         return tree
                     (Nothing, Nothing) -> do
                         Trans.lift $ State.modify (Map.insert v n)
                         return n
                     (Nothing, Just tree) | not $ Set.member v seen -> do
                         let seen' = Set.insert v seen
                         tree' <- CT.restructTreeM (substituteNode seen') tree
                         Trans.lift $ State.modify (Map.insert v tree')
                         return tree'
                     _ -> Except.throwE "recursive conditions"
              substituteNode _ n = return n
              jumpTrees = Map.fromList $ map jumpToNamedTree jumps
              jumpToNamedTree (DefaultJump name) = (name, CT.NodeTrue)
              jumpToNamedTree (Jump name tree) = (name, tree)
