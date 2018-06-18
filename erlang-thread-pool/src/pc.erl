%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Module       : pc
%% Author(s)    : Mina
%% Description  : Process Control
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-module(pc).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% APIs
%%
%%  init
%%  spawn_cntrl
%%  check_process
%%  kill_process
%%  history
%%  destroy
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-export([init/0,spawn_cntrl/1,spawn_cntrl/2,check_process/1,kill_process/1,
         destroy/0,history/0]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Macros
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-define(MAX_NUM_PROCESS,3).
-define(MAX_NUM_HISTORY,2).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Records
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-record(state, {running=[],queued=[],count=0,max=?MAX_NUM_PROCESS,history=[]}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Public Functions APIs
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: init/0
%% Arguments    : N/A
%% Return Value : ok | error
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init()->
    try
        register(process_controller,
                 spawn(fun()-> process_controller(#state{}) end)),
        ok
    catch
        _:_ -> error
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: spawn_cntrl/1
%% Arguments    : Fun:          A fun to run in a process
%% Return Value : {ok,Pid} |{ok,not_queued} |{error, bad_arg} |{error, do init}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
spawn_cntrl(Fun)->
    spawn_cntrl(Fun,queue).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: spawn_cntrl/2
%% Arguments    : Fun:          A fun to run in a process
%%                WhnMaxRchd:   queue | drop
%% Return Value : {ok,Pid} |{ok,not_queued} |{error, bad_arg} |{error, not_init}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
spawn_cntrl(Fun,WhnMaxRchd) when WhnMaxRchd =:= queue; WhnMaxRchd =:= drop ->
    try
        process_controller ! {new_process,{self(),Fun,WhnMaxRchd}},
        receive
            ReturnValue -> ReturnValue
        end
    catch
        _:_ -> {error,"Process Controller is not initialized or is dead"}
    end;
spawn_cntrl(_,_) ->
    {error,bad_arg}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: check_process/1
%% Arguments    : Pid: Process ID
%% Return Value : running |queued |died |{error, Reason}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
check_process(Pid)->
    try
        process_controller ! {check_process, {self(),Pid}},
        receive
            Status -> Status
        end
    catch
        _:_ -> {error,"Process Controller is not initialized or is dead"}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: kill_process/1
%% Arguments    : Pid
%% Return Value : ok |{error,Reason}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
kill_process(Pid)->
    try
        process_controller ! {kill_process, Pid},
        ok
    catch
        _:_ -> {error,"Process Controller is not initialized or is dead"}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: history/0
%% Arguments    : N/A
%% Return Value : ok | {error,Reason}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
history()->
    try
        process_controller ! {fetch_history,self()},
        receive
            History -> History
        end
    catch
        _:_ -> {error,"Process Controller is not initialized or is dead"}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: destroy/0
%% Arguments    : N/A
%% Return Value : ok
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
destroy()->
    try
        process_controller ! {destroy},
        ok
    catch
        _:_ -> ok
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Internal Functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: process_controller/1
%% Arguments    : State | exit
%% Messages     : ok
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
process_controller(exit)  ->
    ok;
process_controller(State) ->
    receive
        {new_process,Args}      -> UpdatedState = new_process(State,Args);
        {check_process,Args}    -> UpdatedState = State, check(State,Args);
        {kill_process,Pid}      -> UpdatedState = State, kill(State,Pid);
        {destroy}               -> UpdatedState = exit, destroy_running(State);
        {'DOWN',_,_,Pid,Reason} -> UpdatedState = process_died(State,Pid,Reason);
        {fetch_history,From}    -> UpdatedState = State, From ! State#state.history;
        _                       -> UpdatedState = State
    end,
    process_controller(UpdatedState).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: new_process/1
%% Arguments    : State
%% Return Value : UpdatedState
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
new_process(State,{From,Fun,WhnMxRchd}) ->
    #state{running=Running,queued=Queued,max=Max,count=Count} = State,
    if
        % Maximum number of spawned processes is reached
        Count >= Max ->
            if
                % Queue the task when maximum is reached
                WhnMxRchd =:= queue ->
                    PrcssId = make_ref(),
                    try
                        % Send process id to the caller
                        From ! {ok,PrcssId},
                        % Update the state adding the process to the queue list
                        State#state{queued=lists:append(Queued,[{PrcssId,Fun}])}
                    catch
                        % Caller Died
                        % Update the state adding the process to the queue list
                        _:_ -> State#state{queued=lists:append(Queued,[{PrcssId,Fun}])}
                    end;
                % Drop the task when maximum is reached
                WhnMxRchd =:= drop ->
                    try
                        % As the task is not queued return that to the caller
                        From ! {ok,not_queued},
                        % State left unchanged
                        State
                    catch
                        % Caller Died
                        _:_ -> State
                    end
            end;
        % Maximum number of spawned processes is not reached
        Count < Max ->
            PrcssId = make_ref(),
            R =
            try
                % Spawn the process
                erlang:monitor(process, Pid = spawn(Fun)),
                {ok,{PrcssId,Pid}}
            catch
                Error:Reason -> {error,{Error,Reason}}
            end,
            try
                % Return the process id to the caller in case of no error
                case R of
                    {ok,_}                  -> From ! {ok,PrcssId};
                    {error,{error,badarg}}  -> From ! {error,badarg};
                    {error,_}               -> From ! {ok,PrcssId}
                end
            catch
                % Caller died
                _:_ -> caller_died
            end,
            % Update the state adding the process if spawned to the running list
            % or to the queue list if spawning failed 
            case R of
                {ok,Entry}  -> State#state{count=Count+1,running=
                                        lists:append(Running,[Entry])};
                {error,{error,badarg}}  -> State;
                {error,_}   -> State#state{queued=
                                        lists:append(Queued,[{PrcssId,Fun}])}
            end
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: process_died/1
%% Arguments    : State
%% Return Value : UpdatedState
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
process_died(State,PidDied,Reason) ->
    #state{running=Running,queued=Queued,count=Count} = State,
    % Remove died process from the running list
    {_,Entry} = find_process(State,PidDied,2),
    UpdatedRunning = Running--[Entry],
    % updating history list adding the died process id and reason
    History =  update_history(State#state.history,{PidDied,Reason}),
    if
        % There are queued processes
        length(Queued) /= 0 ->
                            % Pick one
                            [{PrcssId,Fun}|Q_T] = Queued, 
                            try
                                % spawn it
                                erlang:monitor(process, Pid=spawn(Fun)),
                                % Update the state adding it to the running list
                                % and the count as it is as one process died and 
                                % another one created
                                State#state{queued=Q_T,history=History,running=
                                    lists:append(UpdatedRunning,[{PrcssId,Pid}])}
                            catch
                                % Update the state decrementing the counter as
                                % 1 process died and no other spawned
                                _:_ -> State#state{count=Count-1,history=History,
                                                        running=UpdatedRunning}
                            end;
        % Update the state decrementing the counter as
        % 1 process died and no other spawned
        true               -> State#state{count=Count-1,history=History,
                                                        running=UpdatedRunning}
    end.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: check_pid/1
%% Arguments    : State   : State
%%                PrcssId : Process Id
%% Return Value : running| queued| died
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
check(State, {From,PrcssId})->
    From !
    case find_process(State,PrcssId,1) of
        {running,_} -> running;
        {queued,_}  -> queued;
        died        -> died
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: kill_pid/2
%% Arguments    : State   : State
%%                PrcssId : Process Id
%% Return Value : UpdatedState
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
kill(State, PrcssId)->
    #state{running=Running,queued=Queued} = State,
    case find_process(State,PrcssId,1) of
        {running,{_,Pid}=Entry} -> exit(Pid,normal),
                                   State#state{running=Running--[Entry]};
        {queued,Entry}          -> State#state{queued=Queued--[Entry]};
        died                    -> State
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: destroy_queues/1
%% Arguments    : State
%% Return Value : ok
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
destroy_running(State)->
    lists:map(fun({_,Pid})-> exit(Pid,normal) end, State#state.running),
    ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: find_process/1
%% Arguments    : State   : State
%%                PrcssId : Process Id
%% Return Value : {running,{PrcssId,Pid}} | {queued,{PrcssId,Fun}} | died
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
find_process(State,Id,Pos)->
    case lists:keysearch(Id,Pos,State#state.running) of
        {value,Entry} -> {running,Entry};
        false -> 
            case lists:keysearch(Id,Pos,State#state.queued) of
                {value,Entry}   -> {queued,Entry};
                false           -> died
           end
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Function Name: update_history/1
%% Arguments    : History
%% Return Value : ok
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
update_history(L,Element)->
    History = L++[Element],
    if
        length(History) > ?MAX_NUM_HISTORY  -> [_|UpdatedHistory] = History;
        true                                -> UpdatedHistory = History
    end,
    UpdatedHistory.

