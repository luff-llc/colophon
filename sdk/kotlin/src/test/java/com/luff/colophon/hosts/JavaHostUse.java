package com.luff.colophon.hosts;

import com.luff.colophon.session.ColophonSession;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/** A Java application opening a session cell host through the public API only. */
public final class JavaHostUse {
    private JavaHostUse() {}

    /** A carrier that carries nothing, written in Java. */
    static final class Nowhere implements CellCarrier {
        @Override public void attach(StreamCell cell) { cell.linkUp(); }
        @Override public void detach(StreamCell cell) {}
        @Override public boolean sendSession(String frame, Function0<Unit> lost) { return true; }
    }

    public static SessionCellHost open(ColophonSession session) throws Exception {
        CellHostOptions options = new CellHostOptions(HostAccess.of(session), new Nowhere(), "listening.podcasts", "now-playing", new MemoryClaimStore());
        return SessionCellHost.openFuture(options, event -> Unit.INSTANCE).get(60, TimeUnit.SECONDS);
    }
}
