#!/usr/bin/env python3
"""Launch a no-install presentation, or opt into the real verified demo."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verified', action='store_true', help='Run real OPA + Lean verification (requires setup)')
    parser.add_argument('--port', type=int, default=8787)
    parser.add_argument('--build', metavar='DIRECTORY', help='Write a standalone illustrative website without serving')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('port must be between 1 and 65535')
    if args.verified:
        if args.build:
            parser.error('--build is for the illustrative presentation only')
        required = [ROOT/'tools/bin/opa', ROOT/'proof/.lake/build/bin/guard-kernel']
        if not all(path.is_file() for path in required):
            parser.exit(1, 'Verified tools are missing. Follow the developer guide: install the package, then run python3 tools/bootstrap.py.\n')
        parent = Path(tempfile.mkdtemp(prefix='auth-verified-'))
        return subprocess.call([sys.executable, '-m', 'agent_guard', 'product-demo',
                                '--output', str(parent/'run'), '--serve', '--port', str(args.port)], cwd=ROOT)
    spec = importlib.util.spec_from_file_location('auth_presentation', ROOT/'agent_guard/integration/presentation.py')
    presentation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(presentation)
    output = Path(args.build) if args.build else Path(tempfile.mkdtemp(prefix='auth-presentation-'))
    if args.build and output.exists():
        parser.exit(1, 'Choose a new build directory; existing files are not overwritten.\n')
    presentation.render_site(output, presentation.illustrative_story())
    if args.build:
        print('Presentation website: ' + str((output/'index.html').resolve()))
        return 0

    class Handler(SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ('/', '/index.html', '/technical.html'):
                self.send_error(404)
                return
            super().do_GET()

        def do_HEAD(self):
            if self.path not in ('/', '/index.html', '/technical.html'):
                self.send_error(404)
                return
            super().do_HEAD()

        def log_message(self, *_):
            pass

    try:
        server = ThreadingHTTPServer(('127.0.0.1', args.port), partial(Handler, directory=str(output)))
    except OSError as exc:
        parser.exit(1, f'Cannot start on port {args.port}: {exc}. Try --port 8788.\n')
    print(f'ASAP presentation: http://127.0.0.1:{server.server_port}\nIllustrative mode · no OPA/Lean execution. Ctrl-C to stop.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
