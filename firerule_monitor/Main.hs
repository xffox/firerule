module Main where

import qualified System.Posix.Signals as Signals
import qualified System.IO as SIO
import qualified Text.Printf as Printf
import qualified Options.Applicative as Opt
import qualified Control.Monad.Trans.Except as Except
import qualified Control.Concurrent.MVar as MVar
import Control.Applicative((<**>))
import Data.Semigroup((<>))

import qualified NetRuleBuilder as NetRuleBuilder
import qualified NetRuleExecutor as NetRuleExecutor

data Config = Config {
        path :: String
    }

configParse = Config <$>
    Opt.strOption (
            Opt.long "path" <>
            Opt.short 'p' <>
            Opt.metavar "PATH"
        )

main = do
    config <- Opt.execParser $
        Opt.info (configParse <**> Opt.helper) Opt.fullDesc
    res <- Except.runExceptT $ NetRuleBuilder.readNetRule $ path config
    case res of
      Left err -> fail err
      Right nr -> startMonitor nr

-- current logging is just stdout
setupLogging =
    SIO.hSetBuffering SIO.stdout SIO.NoBuffering

startMonitor nr = do
    setupLogging
    cont <- MVar.newEmptyMVar
    let stopAction = stopMonitor cont
    Signals.installHandler Signals.sigINT
      (Signals.Catch $ stopAction)
      Nothing
    Signals.installHandler Signals.sigTERM
      (Signals.Catch $ stopAction)
      Nothing
    handle <- NetRuleExecutor.runNetRule nr
    MVar.takeMVar cont
    NetRuleExecutor.stopNetRule handle

stopMonitor cont =
    MVar.putMVar cont 0
