module Main where

import qualified System.Posix.Signals as Signals
import qualified System.IO as SIO
import qualified Text.Printf as Printf
import qualified Options.Applicative as Opt
import qualified Control.Monad.Trans.Except as Except
import qualified Control.Concurrent.MVar as MVar
import qualified Control.Exception as Exception
import Control.Applicative((<**>))
import Data.Semigroup((<>))

import qualified DBus.Client as DC

import qualified NetRuleBuilder as NetRuleBuilder
import qualified NetRuleExecutor as NetRuleExecutor
import qualified DBusNetMonitor as DBusNetMonitor

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
    Exception.bracket
        DC.connectSystem
        DC.disconnect
        (\client ->
            Exception.bracket
                (DBusNetMonitor.initNetMonitor client)
                DBusNetMonitor.destroyNetMonitor
                (\monitor ->
                    Exception.bracket
                        (DBusNetMonitor.initNetNotifier client)
                        DBusNetMonitor.destroyNetNotifier
                        (\notifier -> do
                            res <- Except.runExceptT $
                                NetRuleBuilder.readNetRule $ path config
                            case res of
                              Left err ->
                                  fail err
                              Right nr ->
                                  runMonitor monitor notifier nr
                        )
                )
        )

-- current logging is just stdout
setupLogging =
    SIO.hSetBuffering SIO.stdout SIO.NoBuffering

runMonitor monitor notifier nr = do
    setupLogging
    cont <- MVar.newEmptyMVar
    let stopAction = stopMonitor cont
    Signals.installHandler Signals.sigINT
      (Signals.Catch $ stopAction)
      Nothing
    Signals.installHandler Signals.sigTERM
      (Signals.Catch $ stopAction)
      Nothing
    handle <- NetRuleExecutor.runNetRule monitor notifier nr
    MVar.takeMVar cont
    NetRuleExecutor.stopNetRule handle

stopMonitor cont =
    MVar.putMVar cont 0
