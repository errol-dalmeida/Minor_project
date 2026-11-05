"""Run the actual PeerNode TCP mesh acceptance suite."""

import unittest

import test_direct_mesh


def run_network_e2e_test():
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_direct_mesh)
    return unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()


if __name__ == "__main__":
    raise SystemExit(0 if run_network_e2e_test() else 1)
