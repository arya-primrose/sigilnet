"""The WHOLE protocol (capsule join, encrypted thread, posts both ways, removal with key rotation, closed door) over two TcpCarriers on loopback: the same script
(fake_e2e.run) that proves the protocol over the in-memory fake. The protocol layer does not know which carrier it runs on."""
import unittest

from sigilnet import tcplink as TL
from sigilnet.tests import fake_e2e
from sigilnet.tests.test_tcplink import free_base


class TcpEndToEnd(unittest.TestCase):
    def test_the_whole_protocol_runs_over_the_tcp_carrier(self):
        def factory(name, state_dir):
            return TL.TcpCarrier(state_dir, bind="127.0.0.1", port_base=free_base())
        self.assertEqual(fake_e2e.run(factory), "E2E OK")


if __name__ == "__main__":
    unittest.main()
