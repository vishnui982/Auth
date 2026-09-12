import sys

if len(sys.argv) > 1 and sys.argv[1] == "product-demo":
    from .integration.demo import main
    del sys.argv[1]
elif len(sys.argv) > 1 and sys.argv[1] == "v2":
    from .v2.cli import main
    del sys.argv[1]
else:
    from .cli import main

raise SystemExit(main())
