#!/usr/bin/env python3

import os
import argparse
import logging
import sys
import re
import subprocess
import shlex
import yaml
from pathlib import Path
from filefamily_functions import get_ff


def get(args):
    message = 'Executing "{}" command for {}'.format(
        args["command"], args["storage_information"]["path"]
    )
    logger.info(message)
    # Sanity checks
    target_dir = os.path.dirname(args["filename"])
    if not os.path.isdir(target_dir):
        logger.error("Target directory {} not found".format(target_dir))
        sys.exit(31)

    # Get path from uri:
    uri_prefix_template = "{hsmType}://hpss{voPrefix}"
    uri_prefix = uri_prefix_template.format(
        hsmType=args["storage_information"]["hsm"],
        voPrefix=args["vo_configuration"]["fuse_mount"],
    )
    lfn = os.path.relpath(args["uri"], uri_prefix).split("?")[0]
    hpss_filename = os.path.join(args["vo_configuration"]["fuse_mount"], lfn)

    # Construct pftp get command
    pftp_input = "pget {} {}\nquit".format(lfn, args["filename"])
    recall_command = subprocess.run(
        shlex.split(args["pftp_command"]),
        input=pftp_input,
        encoding="ascii",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    logger.debug("recall command returncode: {}".format(recall_command.returncode))
    logger.debug("recall command output:\n" + recall_command.stdout)
    logger.debug("recall command errors:\n" + recall_command.stderr)
    if recall_command.returncode != 0 or len(recall_command.stderr.strip()) > 0:
        logger.error(
            "pftp recall command failed, from {} to {}".format(
                hpss_filename, args["filename"]
            )
        )
        if os.path.isfile(args["filename"]):
            os.remove(args["filename"])
        sys.exit(43)

    # Assuming here, everything went well, so exit script normally
    sys.exit(0)


def remove(args):
    message = 'Executing "{}" command for {}'.format(args["command"], args["uri"])
    logger.info(message)
    # Get path from uri:
    hsmType = re.match(args["uri_prefix_pattern"], args["uri"]).group(0)
    uri_prefix_template = "{hsmType}{voPrefix}"
    uri_prefix = uri_prefix_template.format(
        hsmType=hsmType, voPrefix=args["vo_configuration"]["fuse_mount"]
    )
    lfn = os.path.relpath(args["uri"], uri_prefix).split("?")[0]
    pnfsid_from_uri = args["uri"].split("?")[1].replace("pnfsid=", "")
    hpss_filename = os.path.join(args["vo_configuration"]["fuse_mount"], lfn)

    # Checking, whether the file exists
    pftp_filecheck_input = "\n".join(
        [
            "ls {}".format(lfn),
            "quit",
        ]
    )
    filecheck_command = subprocess.run(
        shlex.split(args["pftp_command"]),
        input=pftp_filecheck_input,
        encoding="ascii",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    logger.debug(
        "filecheck command returncode: {}".format(filecheck_command.returncode)
    )
    logger.debug("filecheck command output:\n" + filecheck_command.stdout)
    logger.debug("filecheck command errors:\n" + filecheck_command.stderr)
    if "Could not stat" in filecheck_command.stdout:
        logger.warning(
            "File {} does not exist on HPSS. Nothing to do, consider deletion as successful".format(
                hpss_filename
            )
        )
        sys.exit(0)

    # Construct pftp pnfsid check command
    pftp_pnfsidcheck_input = "\n".join(
        ["site udaget {} /hpss/pnfsid value".format(lfn), "quit"]
    )
    pnfsidcheck_command = subprocess.run(
        shlex.split(args["pftp_command"]),
        input=pftp_pnfsidcheck_input,
        encoding="ascii",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    logger.debug(
        "pnfsidcheck command returncode: {}".format(pnfsidcheck_command.returncode)
    )
    logger.debug("pnfsidcheck command output:\n" + pnfsidcheck_command.stdout)
    logger.debug("pnfsidcheck command errors:\n" + pnfsidcheck_command.stderr)
    if (
        pnfsidcheck_command.returncode != 0
        or len(pnfsidcheck_command.stderr.strip()) > 0
    ):
        logger.error("pftp pnfsidcheck command failed for {}".format(hpss_filename))
        sys.exit(36)

    # Extract the pnfsid from stdout and compare with the one in URI
    pnfsid_from_hpss = None
    for stdout in pnfsidcheck_command.stdout.split("\n"):
        if stdout.strip().startswith("/hpss/pnfsid="):
            pnfsid_from_hpss = stdout.strip().replace("/hpss/pnfsid=", "").strip()

    # pnfsID not set in HPSS. Should be followed up manually
    if pnfsid_from_hpss is None:
        logger.error(
            "pnfsid not set in HPSS. Consider deletion as failed for {}. Please check manually for the reason.".format(
                hpss_filename
            )
        )
        sys.exit(36)

    # pnfsID not equal. Possible reason: more recent pnfsID in HPSS due to an overwrite
    if pnfsid_from_hpss != pnfsid_from_uri:
        logger.warning(
            "pnfsid not equal between URI ({}) and HPSS ({}). However, consider deletion successful for {}.".format(
                pnfsid_from_uri, pnfsid_from_hpss, args["uri"]
            )
        )
        sys.exit(0)

    # Construct pftp delete command
    pftp_input = "\n".join(["delete {}".format(lfn), "quit"])
    delete_command = subprocess.run(
        shlex.split(args["pftp_command"]),
        input=pftp_input,
        encoding="ascii",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    logger.debug("delete command returncode: {}".format(delete_command.returncode))
    logger.debug("delete command output:\n" + delete_command.stdout)
    logger.debug("delete command errors:\n" + delete_command.stderr)
    if delete_command.returncode != 0 or len(delete_command.stderr.strip()) > 0:
        logger.error("pftp delete command failed for {}".format(hpss_filename))
        sys.exit(36)

    # Assuming here, everything went well, so exit script normally
    logger.info("remove command successful for {}".format(args["uri"]))
    sys.exit(0)


def put(args):
    message = 'Executing "{}" command for {}'.format(
        args["command"], args["storage_information"]["path"]
    )
    logger.info(message)
    filesize = 0

    # Sanity checks
    if not os.path.isfile(args["filename"]):
        logger.error("File {} not found".format(args["filename"]))
        sys.exit(31)
    else:
        filesize = os.path.getsize(args["filename"])
        if filesize == 0:
            logger.error("File {} empty".format(args["filename"]))
            sys.exit(32)
        elif filesize != int(args["storage_information"]["size"]):
            logger.error(
                "Size of file {} is {} Bytes, but expecting {} Bytes".format(
                    args["filename"], filesize, int(args["storage_information"]["size"])
                )
            )
            sys.exit(32)

    # Determine filefamily and submit pftp put command
    lfn = os.path.relpath(
        args["storage_information"]["path"], args["vo_configuration"]["pnfs_path"]
    )
    hpss_filename = os.path.join(args["vo_configuration"]["fuse_mount"], lfn)
    filefamily = -1
    hpss_dataset = "dummy"
    if any([d in hpss_filename for d in args["vo_configuration"]["test_folders"]]):
        filefamily = get_ff(hpss_filename, args["vo_configuration"], test_mode=True)
        logger.info(
            "Running in test mode for file {}".format(
                args["storage_information"]["path"]
            )
        )
        logger.debug(
            "used test folders:\n" + "\n".join(args["vo_configuration"]["test_folders"])
        )
    # Using filename as entity in case of test VO
    elif args["vo_configuration"]["VO"] == "test":
        filefamily = get_ff(hpss_filename, args["vo_configuration"])
    else:
        match = re.match(args["vo_configuration"]["file_pattern"], hpss_filename)
        if match:
            hpss_dataset = match.group(1)
        # Check, if it is required to check the size of a dataset via extended attributes
        if args["vo_configuration"]["bigdata_filefamilies"]:
            # Trying to get information on dataset-size extended attribute:
            bigdata_attribute = args["vo_configuration"]["bigdata_attribute"]
            if bigdata_attribute in args["storage_information"]:
                if args["storage_information"][bigdata_attribute] == "None":
                    logger.warning(
                        "Extended attribute 'dataset-size' is 'None' for file {}. Assuming normal operation with dataset-based file families.".format(
                            args["storage_information"]["path"]
                        )
                    )
                    filefamily = get_ff(hpss_dataset, args["vo_configuration"])
                else:
                    dataset_size = int(args["storage_information"][bigdata_attribute])
                    logger.debug(
                        "Found dataset-size = {} Bytes for file {}".format(
                            dataset_size, args["storage_information"]["path"]
                        )
                    )
                    if dataset_size >= int(
                        float(args["vo_configuration"]["bigdata_threshold"])
                    ):
                        logger.debug(
                            "Consider dataset of file {} being big. Using file-based bigdata file families".format(
                                args["storage_information"]["path"]
                            )
                        )
                        filefamily = get_ff(
                            hpss_filename, args["vo_configuration"], big_data=True
                        )
                    else:
                        logger.debug(
                            "Consider dataset of file {} being small. Using dataset-based file families".format(
                                args["storage_information"]["path"]
                            )
                        )
                        filefamily = get_ff(hpss_dataset, args["vo_configuration"])
            else:
                logger.warning(
                    "Extended attribute 'dataset-size' not found for file {}. Assuming normal operation with dataset-based file families.".format(
                        args["storage_information"]["path"]
                    )
                )
                filefamily = get_ff(hpss_dataset, args["vo_configuration"])
        else:
            filefamily = get_ff(hpss_dataset, args["vo_configuration"])
    if filefamily < 0:
        logger.error(
            "Unable to determine filefamily for dataset {} of file {}".format(
                hpss_dataset, lfn
            )
        )
        sys.exit(37)

    logger.debug("Determined filefamily for file {}: {}".format(lfn, filefamily))

    if len(args["storage_information"]["flag-c"]) == 0:
        logger.error("Could not find an entry for adler32 checksum")
        sys.exit(38)
    # Covering the case, when multiple checksums are provided - pick the one with length 8, since this is adler32
    checksums = [
        checksum_info.split(":")[1]
        for checksum_info in args["storage_information"]["flag-c"].split(",")
        if len(checksum_info.split(":")[1]) == 8
    ]
    if len(checksums) == 0:
        logger.error("Could not find an entry for adler32 checksum")
        sys.exit(38)

    # Constructing uri
    uri_template = "{hsmType}://hpss{bfid}?pnfsid={pnfsid}"
    uri = uri_template.format(
        hsmType=args["storage_information"]["hsm"],
        bfid=hpss_filename,
        pnfsid=args["pnfsID"],
    )

    # Checking, whether the file already exists
    pftp_filecheck_input = "\n".join(
        [
            "ls {}".format(lfn),
            "quit",
        ]
    )
    filecheck_command = subprocess.run(
        shlex.split(args["pftp_command"]),
        input=pftp_filecheck_input,
        encoding="ascii",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    logger.debug(
        "filecheck command returncode: {}".format(filecheck_command.returncode)
    )
    logger.debug("filecheck command output:\n" + filecheck_command.stdout)
    logger.debug("filecheck command errors:\n" + filecheck_command.stderr)
    if "Could not stat" not in filecheck_command.stdout:
        logger.warning(
            "File {} already exists on HPSS. Comparing checksums of request and file on HPSS".format(
                hpss_filename
            )
        )

        # Getting checksum of file on HPSS
        pftp_checksumcheck_input = "\n".join(
            [
                "quote opts mlst x.hpsshash",
                "quote mlst {}".format(lfn),
                "quit",
            ]
        )

        checksumcheck_command = subprocess.run(
            shlex.split(args["pftp_command"]),
            input=pftp_checksumcheck_input,
            encoding="ascii",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logger.debug(
            "checksumcheck command returncode: {}".format(
                checksumcheck_command.returncode
            )
        )
        logger.debug("checksumcheck command output:\n" + checksumcheck_command.stdout)
        logger.debug("checksumcheck command errors:\n" + checksumcheck_command.stderr)
        if (
            checksumcheck_command.returncode != 0
            or len(checksumcheck_command.stderr.strip()) > 0
        ):
            logger.error(
                "Something went wrong when getting checksum for {} from HPSS. Rejecting write request.".format(
                    hpss_filename
                )
            )
            sys.exit(39)
        for stdout in checksumcheck_command.stdout.split("\n"):
            if stdout.strip().startswith("x.hpsshash="):
                hpsshashtype, hpsshashuser, hpsshashvalue, hpsshashflags = (
                    stdout.strip().split()[0].replace("x.hpsshash=", "").split(":")
                )

                # Compare hpss checksum with request value
                if checksums[0] == hpsshashvalue:
                    logger.warning(
                        "Checksums between file on HPSS and write request are equal ({}). Setting only the new pnfsID for {}".format(
                            hpsshashvalue, args["storage_information"]["path"]
                        )
                    )
                    pftp_updatepnfsid_input = "\n".join(
                        [
                            "site udaset {} /hpss/pnfsid {}".format(
                                lfn, args["pnfsID"]
                            ),
                            "site udaget {} /hpss/pnfsid value".format(lfn),
                            "quit",
                        ]
                    )
                    # Assuming that an update of pnfsid will be successful at some point
                    pnfsid_updated = False
                    while not pnfsid_updated:
                        updatepnfsid_command = subprocess.run(
                            shlex.split(args["pftp_command"]),
                            input=pftp_updatepnfsid_input,
                            encoding="ascii",
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        logger.debug(
                            "updatepnfsid command returncode: {}".format(
                                updatepnfsid_command.returncode
                            )
                        )
                        logger.debug(
                            "updatepnfsid command output:\n"
                            + updatepnfsid_command.stdout
                        )
                        logger.debug(
                            "updatepnfsid command errors:\n"
                            + updatepnfsid_command.stderr
                        )
                        pnfsid_updated = (
                            updatepnfsid_command.returncode == 0
                            and len(updatepnfsid_command.stderr.strip()) == 0
                        )
                    logger.warning(
                        "Updating pnfsID worked for the file with checksums in HPSS and write request being equal ({}). Consider write request successful for {}".format(
                            hpsshashvalue, args["storage_information"]["path"]
                        )
                    )
                    print(uri)
                    sys.exit(0)
                else:
                    logger.warning(
                        "File {} on HPSS has a different checksum ({}) than given in this write request ({}). Assuming the later copy is valid and proceeding with overwriting".format(
                            hpss_filename, hpsshashvalue, checksums[0]
                        )
                    )

    # Constructing pftp write command
    pftp_input = "\n".join(
        [
            "site setcos {}".format(args["vo_configuration"]["cos"]),
            "site setfam {}".format(filefamily),
        ]
        + [
            "mkdir {}".format(parentpath.as_posix())
            for parentpath in reversed(Path(lfn).parents)
            if parentpath.as_posix() != "."
        ]
        + [
            "pput {} {}".format(args["filename"], lfn),
            "site sethash {} ftpuser adler32 {}".format(lfn, checksums[0]),
            "site udaset {} /hpss/pnfsid {}".format(lfn, args["pnfsID"]),
            "site udaget {} /hpss/pnfsid value".format(lfn),
            "quit",
        ]
    )
    write_command = subprocess.run(
        shlex.split(args["pftp_command"]),
        input=pftp_input,
        encoding="ascii",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    logger.debug("write command returncode: {}".format(write_command.returncode))
    logger.debug("write command output:\n" + write_command.stdout)
    logger.debug("write command errors:\n" + write_command.stderr)
    if write_command.returncode != 0 or len(write_command.stderr.strip()) > 0:
        logger.error(
            "pftp write command failed, from {} to {}".format(
                args["filename"], hpss_filename
            )
        )
        delete_input = "\n".join(
            [
                "site setcos {}".format(args["vo_configuration"]["cos"]),
                "site setfam {}".format(filefamily),
                "delete {}".format(lfn),
                "quit",
            ]
        )
        delete_command = subprocess.run(
            shlex.split(args["pftp_command"]),
            input=delete_input,
            encoding="ascii",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logger.debug(
            "delete corrupted command returncode: {}".format(delete_command.returncode)
        )
        logger.debug("delete corrupted command output:\n" + delete_command.stdout)
        logger.debug("delete corrupted command errors:\n" + delete_command.stderr)
        check_trashcan_input = "\n".join(
            [
                "site setcos {}".format(args["vo_configuration"]["cos"]),
                "site setfam {}".format(filefamily),
                "ls {}".format(os.path.join(".Trash", os.path.basename(lfn + "*"))),
                "quit",
            ]
        )
        check_trashcan_command = subprocess.run(
            shlex.split(args["pftp_command"]),
            input=check_trashcan_input,
            encoding="ascii",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logger.debug(
            "check trashcan command returncode: {}".format(
                check_trashcan_command.returncode
            )
        )
        logger.debug("check trashcan command output:\n" + check_trashcan_command.stdout)
        logger.debug("check trashcan command errors:\n" + check_trashcan_command.stderr)
        stdoutlist = [l.strip() for l in check_trashcan_command.stdout.split("\n")]
        for l in stdoutlist:
            if l.startswith(".Trash"):
                delete_trashcan_input = "\n".join(
                    [
                        "site setcos {}".format(args["vo_configuration"]["cos"]),
                        "site setfam {}".format(filefamily),
                        "delete {}".format(l),
                        "quit",
                    ]
                )
                delete_trashcan_command = subprocess.run(
                    shlex.split(args["pftp_command"]),
                    input=delete_trashcan_input,
                    encoding="ascii",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                logger.debug(
                    "delete from trashcan command returncode: {}".format(
                        delete_trashcan_command.returncode
                    )
                )
                logger.debug(
                    "delete from trashcan command output:\n"
                    + delete_trashcan_command.stdout
                )
                logger.debug(
                    "delete from trashcan command errors:\n"
                    + delete_trashcan_command.stderr
                )
                break
        sys.exit(42)

    # Assuming, that the file was successfully written to HPSS, perform a checksum test
    hpsssum = args["hpsssum_command"].format(
        keytab=args["vo_configuration"]["keytab"],
        hpssuser=args["vo_configuration"]["hpssuser"],
        hpsspath=hpss_filename,
    )
    hpsssum_command = subprocess.run(
        shlex.split(hpsssum), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    logger.debug("hpsssum command returncode: {}".format(hpsssum_command.returncode))
    logger.debug("hpsssum command output:\n" + hpsssum_command.stdout.decode("utf-8"))
    logger.debug("hpsssum command errors:\n" + hpsssum_command.stderr.decode("utf-8"))
    if (
        hpsssum_command.returncode != 0
        or len(hpsssum_command.stderr.decode("utf-8").strip()) > 0
    ):
        logger.error("hpsssum check failed for {}".format(hpss_filename))
        returncode = 42  # Can be changed to a suspending exit code, in case the input file has wrong checksum

        logger.debug(
            "Calculating checksum for dCache input file at {}".format(args["filename"])
        )
        hpsssum_local = args["hpsssum_local_command"].format(localpath=args["filename"])
        hpsssum_local_command = subprocess.run(
            shlex.split(hpsssum_local), stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        logger.debug(
            "hpsssum local command returncode: {}".format(
                hpsssum_local_command.returncode
            )
        )
        logger.debug(
            "hpsssum local command output:\n"
            + hpsssum_local_command.stdout.decode("utf-8")
        )
        logger.debug(
            "hpsssum local command errors:\n"
            + hpsssum_local_command.stderr.decode("utf-8")
        )
        if (
            hpsssum_local_command.returncode != 0
            or len(hpsssum_local_command.stderr.decode("utf-8").strip()) > 0
        ):
            logger.error("hpsssum local check failed for {}".format(args["filename"]))
            returncode = 32
        else:
            logger.debug(
                "Searching for checksum in output of hpsssum local check for {}".format(
                    args["filename"]
                )
            )
            stdoutlist = [
                l.strip()
                for l in hpsssum_local_command.stdout.decode("utf-8")
                .strip()
                .split("\n")
            ]
            # Searching for the line containing the checksum
            input_checksum = None
            for l in stdoutlist:
                if args["filename"] in l:
                    input_checksum = l.split()[0]
                    break
            if input_checksum:
                if input_checksum == checksums[0]:
                    logger.debug(
                        "Checksum of input file {} is correct {}. Problem encountered on HPSS side. Allowing dCache to repeat transfer.".format(
                            args["filename"], input_checksum
                        )
                    )
                    returncode = 42
                else:
                    logger.error(
                        "Checksum of input file {} has a different value ({}) than expected from dCache ({}). Suspending transfer request.".format(
                            args["filename"], input_checksum, checksums[0]
                        )
                    )
                    returncode = 32
            else:
                logger.error(
                    "hpsssum local check did not provide checksum for {}".format(
                        args["filename"]
                    )
                )
                returncode = 32

        # General cleanup before exiting the script with error
        delete_input = "\n".join(
            [
                "site setcos {}".format(args["vo_configuration"]["cos"]),
                "site setfam {}".format(filefamily),
                "delete {}".format(lfn),
                "quit",
            ]
        )
        delete_command = subprocess.run(
            shlex.split(args["pftp_command"]),
            input=delete_input,
            encoding="ascii",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logger.debug(
            "delete corrupted command returncode: {}".format(delete_command.returncode)
        )
        logger.debug("delete corrupted command output:\n" + delete_command.stdout)
        logger.debug("delete corrupted command errors:\n" + delete_command.stderr)
        check_trashcan_input = "\n".join(
            [
                "site setcos {}".format(args["vo_configuration"]["cos"]),
                "site setfam {}".format(filefamily),
                "ls {}".format(os.path.join(".Trash", os.path.basename(lfn + "*"))),
                "quit",
            ]
        )
        check_trashcan_command = subprocess.run(
            shlex.split(args["pftp_command"]),
            input=check_trashcan_input,
            encoding="ascii",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logger.debug(
            "check trashcan command returncode: {}".format(
                check_trashcan_command.returncode
            )
        )
        logger.debug("check trashcan command output:\n" + check_trashcan_command.stdout)
        logger.debug("check trashcan command errors:\n" + check_trashcan_command.stderr)
        stdoutlist = [l.strip() for l in check_trashcan_command.stdout.split("\n")]
        for l in stdoutlist:
            if l.startswith(".Trash"):
                delete_trashcan_input = "\n".join(
                    [
                        "site setcos {}".format(args["vo_configuration"]["cos"]),
                        "site setfam {}".format(filefamily),
                        "delete {}".format(l),
                        "quit",
                    ]
                )
                delete_trashcan_command = subprocess.run(
                    shlex.split(args["pftp_command"]),
                    input=delete_trashcan_input,
                    encoding="ascii",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                logger.debug(
                    "delete from trashcan command returncode: {}".format(
                        delete_trashcan_command.returncode
                    )
                )
                logger.debug(
                    "delete from trashcan command output:\n"
                    + delete_trashcan_command.stdout
                )
                logger.debug(
                    "delete from trashcan command errors:\n"
                    + delete_trashcan_command.stderr
                )
                break
        sys.exit(returncode)

    # After a successful checksum test, everything has worked out properly.
    logger.info(
        "put command successful for {}".format(args["storage_information"]["path"])
    )
    print(uri)
    sys.exit(0)


def valid_storage_information(storage_information: str) -> dict:
    try:
        storage_information_dict = dict(
            si_setting.split("=", 1)
            for si_setting in storage_information.split(";")
            if si_setting
        )
        si_mandatory = set(["hsm", "path", "flag-c", "store"])
        if not all(si in storage_information_dict for si in si_mandatory):
            msg = f"Not all mandatory storage information given. Expecting: {si_mandatory}"
            raise argparse.ArgumentTypeError(msg)
        return storage_information_dict
    except argparse.ArgumentTypeError as e:
        raise argparse.ArgumentTypeError(str(e))
    except Exception as e:
        raise argparse.ArgumentTypeError(
            "Incorrect format of storage information. Expecting <key>=<value> pairs, separated by ';'"
        )


def vo_from_si(args):
    VO = None
    for vo in args["vo_list"]:
        if vo in args["storage_information"]["store"]:
            VO = vo
            break
    logger.info(
        'Determined VO "{}" from "store" attribute of storage information, being equal to "{}"'.format(
            VO, args["storage_information"]["store"]
        )
    )
    return VO


def vo_from_uri(args):
    hpsspath = args["uri"].split("//hpss")[-1]
    VO = hpsspath.strip("/").split("/")[0].replace("GridKa-", "").lower()
    logger.info(
        'Determined VO "{}" from "uri", being equal to "{}"'.format(VO, args["uri"])
    )
    return VO


if __name__ == "__main__":
    where = os.path.dirname(os.path.realpath(__file__))

    script_configuration = yaml.load(
        open(os.path.join(where, "script_configuration.yaml"), "r"),
        Loader=yaml.FullLoader,
    )

    parser = argparse.ArgumentParser(
        description="dc2hpss.py is a script to communicate between dCache and HPSS. It can be used to put, get, or remove files on HPSS",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dump-configuration",
        type=str,
        default=None,
        help="Path to the file where to dump store the provided configuration. Only dump, no further execution.",
    )
    script_conf = parser.add_argument_group(
        title="script configuration",
        description="Extracted from script_configuration.yaml by default",
    )
    script_conf.add_argument(
        "--pftp-command",
        type=str,
        help="Command including all necessary options to call the pftp client from HPSS",
    )
    script_conf.add_argument(
        "--hpsssum-command",
        type=str,
        help="Command including all necessary options to run checksum verification on HPSS",
    )
    script_conf.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Choice for the logging level",
    )
    script_conf.add_argument(
        "--log-output", type=str, help="Path to store the logging output"
    )
    script_conf.add_argument(
        "--vo-list", type=str, nargs="*", help="List of allowed VO's"
    )
    script_conf.add_argument(
        "--uri-prefix-pattern",
        type=str,
        help="Prefix pattern for URI to extract the HPSS path",
    )

    parser.set_defaults(**script_configuration)
    subcommands = parser.add_subparsers(title="subcommands", dest="command")

    parser_put = subcommands.add_parser(
        "put",
        help="Subcommand to write the file from dCache to HPSS. More details via 'put -h'",
    )
    parser_put.add_argument(
        "pnfsID", type=str, help="Unique identifier of the file within dCache instance"
    )
    parser_put.add_argument(
        "filename", type=str, help="Full path of the local file to be copied to HPSS"
    )
    parser_put.add_argument(
        "-si",
        "--storage-information",
        type=valid_storage_information,
        required=True,
        help="Storage attributes of a file",
    )
    parser_put.set_defaults(determine_vo=vo_from_si, execute=put)

    parser_get = subcommands.add_parser(
        "get",
        help="Subcommand to recall the file from HPSS to dCache. More details via 'get -h'",
    )
    parser_get.add_argument(
        "pnfsID", type=str, help="Unique identifier of the file within dCache instance"
    )
    parser_get.add_argument(
        "filename",
        type=str,
        help="Full path of the local file where a file from HPSS should be written to",
    )
    parser_get.add_argument(
        "-si",
        "--storage-information",
        type=valid_storage_information,
        required=True,
        help="Storage attributes of a file",
    )
    parser_get.add_argument(
        "-uri",
        "--storage-uri",
        dest="uri",
        type=str,
        required=True,
        help="Unique resource identifier returned by dc2hpss.py after the corresponding file was written to HPSS",
    )
    parser_get.set_defaults(determine_vo=vo_from_si, execute=get)

    parser_remove = subcommands.add_parser(
        "remove",
        help="Subcommand to erase the file from HPSS. More details via 'remove -h'",
    )
    parser_remove.add_argument(
        "-uri",
        "--storage-uri",
        dest="uri",
        type=str,
        required=True,
        help="Unique resource identifier returned by dc2hpss.py after the corresponding file was written to HPSS",
    )
    parser_remove.set_defaults(determine_vo=vo_from_uri, execute=remove)

    args = vars(parser.parse_args())
    if not args["command"]:
        parser.print_usage()
        sys.exit(1)

    logger = logging.getLogger("dc2hpss.py")
    logger.setLevel(args["log_level"])

    formatter = logging.Formatter("%(asctime)s | %(name)s | %(levelname)s: %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(args["log_level"])

    file_handler = logging.FileHandler(filename=args["log_output"])
    file_handler.setFormatter(formatter)
    file_handler.setLevel(args["log_level"])

    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    logger.debug("Obtained command from dCache:\n" + " ".join(sys.argv))

    VO = args["determine_vo"](args)
    if VO is None:
        logger.error("Could not determine VO")
        sys.exit(1)
    args["vo_configuration"] = yaml.load(
        open(os.path.join(where, "vo_configuration/{}.yaml".format(VO)), "r"),
        Loader=yaml.FullLoader,
    )

    if args["dump_configuration"]:
        with open(args["dump_configuration"], "w") as dump:
            content = yaml.dump(args, default_flow_style=False)
            print(content)
            yaml.dump(args, dump, indent=2)
            logger.warning("Dump created. Exiting script")
            sys.exit(0)
    # Check that binaries hpsssum and pftp are there:
    pftp_client = shlex.split(args["pftp_command"])[0]
    if not os.path.isfile(pftp_client):
        logger.error("pftp client does not exist: {}".format(pftp_client))
        sys.exit(1)
    hpsssum_client = shlex.split(args["hpsssum_command"])[0]
    if not os.path.isfile(hpsssum_client):
        logger.error("hpsssum client does not exist: {}".format(hpsssum_client))
        sys.exit(1)

    args["execute"](args)
