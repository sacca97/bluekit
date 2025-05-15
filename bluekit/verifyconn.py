import subprocess
import argparse
import re
import os
from pathlib import Path

from bluekit.constants import (
    COMMAND_CONNECT,
    COMMAND_INFO,
    REGEX_COMMAND_CONNECT,
    NUMBER_OF_DOS_TESTS,
    MAX_NUMBER_OF_DOS_TEST_TO_FAIL,
)
from bluekit.constants import (
    RETURN_CODE_NOT_VULNERABLE,
    RETURN_CODE_ERROR,
    RETURN_CODE_NONE_OF_4_STATE_OBSERVED,
    RETURN_CODE_UNDEFINED,
    RETURN_CODE_VULNERABLE,
)
from bluekit.constants import OUTPUT_DIRECTORY
from pybtool.device import Device

RETVAL_TARGET_NOT_AVAILABLE = 0
RETVAL_TARGET_CONN_ONLY = 1
RETVAL_TARGET_PAIRABLE = 2
RETVAL_TARGET_ADV_ONLY = 3
RETVAL_TARGET_ADV_CONN = 4
RETVAL_TARGET_ADV_CONN_PAIRABLE = 5


def check_device_status(target: str) -> int:
    """
    Check the status of a Bluetooth device by scanning, connecting, and pairing.
    Returns:
        int:
            0: Not found, not connectable
            1: Not found, connectable, not pairable
            2: Not found, connectable, pairable
            3: Found, not connectable
            4: Found, connectable, not pairable
            5: Found, connectable, pairable
    """
    # Initialize the device, default dev ID is 0
    device = Device()
    device.power_on()

    scan_success = device.scan(target=target)
    connect_success = device.connect(target)

    if not connect_success:
        return 0 if not scan_success else 3

    pair_success = device.pair()

    if not pair_success:
        return 1 if not scan_success else 4

    device.disconnect()
    device.power_off()

    return 2 if not scan_success else 5


def dos_checker(target: str):
    try:
        not_available = 0
        while True:
            # for i in range(NUMBER_OF_DOS_TESTS):
            status = check_device_status(target)
            if status in (1, 2, 4, 5):  # Connectable and/or pairable
                return RETURN_CODE_NOT_VULNERABLE, str(not_available)

            not_available += 1

            if (
                not_available > MAX_NUMBER_OF_DOS_TEST_TO_FAIL
                or not_available > NUMBER_OF_DOS_TESTS
            ):
                return RETURN_CODE_VULNERABLE, str(not_available)
    except Exception as e:
        return RETURN_CODE_ERROR, str(e)


# def dos_checker(target):
#     try:
#         try:
#             cont = True
#             down_times = 0
#             not_pairable = 0
#             while cont:
#                 for i in range(NUMBER_OF_DOS_TESTS):
#                     available = check_availability(target)
#                     if available:
#                         pairable = check_connectivity(target)
#                         if not pairable:
#                             down_times += 1
#                             not_pairable += 1
#                         else:
#                             break
#                     else:
#                         down_times += 1
#                 break
#         except Exception as e:
#             return RETURN_CODE_ERROR, str(e)

#         # NEEDS BETTER LOGIC

#         if down_times > MAX_NUMBER_OF_DOS_TEST_TO_FAIL:
#             if not_pairable > MAX_NUMBER_OF_DOS_TEST_TO_FAIL:
#                 return RETURN_CODE_VULNERABLE, str(down_times)
#             elif down_times == NUMBER_OF_DOS_TESTS:
#                 return RETURN_CODE_VULNERABLE, str(down_times)
#         else:
#             return RETURN_CODE_NOT_VULNERABLE, str(down_times)
#     except Exception as e:
#         return RETURN_CODE_ERROR, str(e)


# def check_availability(target):
#     try:
#         proc_out = subprocess.check_output(
#             COMMAND_INFO.format(target=target), shell=True, stderr=subprocess.PIPE
#         )
#         # Write output to hciinfo.log even when device is not available
#         log_dir = OUTPUT_DIRECTORY.format(target=target, exploit="recon")
#         Path(log_dir).mkdir(exist_ok=True, parents=True)
#         with open(log_dir + "hciinfo.log", "w") as f:
#             f.write(proc_out.decode())
#     except subprocess.CalledProcessError as e:
#         if (
#             e.output
#             == b"Can't create connection: Input/output error\nRequesting information ...\n"
#         ):
#             print("Device is down")
#         # Write error output to hciinfo.log for report generation
#         log_dir = OUTPUT_DIRECTORY.format(target=target, exploit="recon")
#         Path(log_dir).mkdir(exist_ok=True, parents=True)
#         with open(log_dir + "hciinfo.log", "w") as f:
#             f.write(e.output.decode())
#         return False
#     # print("Availability - True")
#     return True


# def check_connectivity(target):
#     try:
#         proc_out = subprocess.check_output(
#             COMMAND_CONNECT.format(target=target), shell=True, stderr=subprocess.STDOUT
#         )
#         print("Successful check - Device connectivity is checked")
#     except subprocess.CalledProcessError as e:
#         # print("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
#         text = e.output.decode()
#         try:
#             mm = re.compile(REGEX_COMMAND_CONNECT.format(target=target))
#             output = mm.search(text).group()
#             print("Partical check - Device connectivity is checked")
#             return True
#         except AttributeError as e:
#             print("Device is offline")
#         return False
#     # print("Connectability- True")
#     return True


# def check_target(self, target):
#     cont = True
#     while cont:
#         for i in range(10):
#             available = check_availability(target)
#             if available:
#                 pairable = check_connectivity(target)
#                 if not pairable:
#                     inp = self.command_input()
#                 else:
#                     return True
#         if not available:
#             inp = self.command_input()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t", "--target", required=False, type=str, help="target MAC address"
    )
    parser.add_argument(
        "-a", "--availability", required=False, type=bool, help="check availability"
    )
    parser.add_argument(
        "-c", "--connectivity", required=False, type=bool, help="check connectivity"
    )
    args = parser.parse_args()

    if args.target:
        if args.availability:
            check_availability(args.target)
        if args.connectivity:
            check_connectivity(args.target)

    else:
        parser.print_help()
