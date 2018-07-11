module Firerule.Format.RuleParser(parseFirewall, parseNamespace,
    Rule(..), Jump(..), Firewall(..), Condition(..)) where

import qualified Control.Monad as M
import qualified Data.Char as Char
import qualified Data.Maybe as Maybe
import qualified Data.List as List
import qualified Text.Parsec as Parsec
import qualified Text.Printf as Printf
import qualified Data.Functor.Identity as Identity
import Text.Parsec((<|>))

import qualified Firerule.CondTree as CT
import qualified Firerule.IPv4 as IPv4
import qualified Firerule.IPv6 as IPv6

data Condition = Condition [String]
    deriving Show
data Rule = Rule String [Jump]
    deriving Show
data Jump = DefaultJump String | Jump String (CT.CondTree Condition)
    deriving Show
data Firewall = Firewall [Rule]
    deriving Show

data Argument = Argument String | TreeArgument (CT.CondTree [Argument])

parseFirewall :: String -> Either String Firewall
parseFirewall inp = case Parsec.parse rules "inp" inp of
                      Right v -> Right v
                      Left v -> Left $ "parse failed: " ++ (show v)

parseNamespace :: String -> Either String [String]
parseNamespace inp = case Parsec.parse namespace "inp" inp of
                       Right v -> Right v
                       Left v -> Left $ "parse failed: " ++ (show v)

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

clauseAtom =
    do {
       c <- condition;
       return $ CT.Leaf c
       }

notClause =
    Parsec.try $ do
        Parsec.spaces
        Parsec.char '!'
        Parsec.spaces
        fmap CT.NodeNot $
            clauseAtom

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

namespace = Parsec.sepBy1 (Parsec.many1 Parsec.alphaNum) (Parsec.char '.')

expandConditionTree = expandConditionTree' (CT.Leaf [])
    where
        expandConditionTree' ptr (CT.Leaf args) =
            expandConditionArgs ptr args
        expandConditionTree' ptr CT.NodeTrue = ptr
        expandConditionTree' ptr CT.NodeFalse = ptr
        expandConditionTree' ptr (CT.NodeNot n) =
            expandConditionTree' (CT.NodeNot ptr) n
        expandConditionTree' ptr (CT.NodeOr left right) =
            CT.NodeOr (expandConditionTree' ptr left)
                (expandConditionTree' ptr right)
        expandConditionTree' ptr (CT.NodeAnd left right) =
            CT.NodeAnd (expandConditionTree' ptr left)
                (expandConditionTree' ptr right)
        expandConditionArgs n [] = n
        expandConditionArgs n ((Argument s):args) =
            expandConditionArgs (fmap (\rs -> rs ++ [s]) n) args
        expandConditionArgs n ((TreeArgument t):args) =
            expandConditionArgs (expandConditionTree' n t) args
