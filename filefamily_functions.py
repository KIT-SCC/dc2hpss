import hashlib
import os


def get_ff(entity, vo_configuration, test_mode=False, big_data=False) -> int:
    # In case of test mode, use files as entity and 5 ff's are used
    if test_mode:
        if len(vo_configuration["test_filefamilies"]) != 5:
            # Could not determine ff, since wrong number of test ff's
            return -1
        else:
            ds_hash = hashlib.sha1(os.path.dirname(entity).encode("utf-8")).hexdigest()
            ff_index = int(ds_hash[:2], 16) % 5
            return vo_configuration["test_filefamilies"][ff_index]
    # Special case of production mode, where big datasets are distributed among bigdata file families. Using thereby file names for hash
    elif big_data:
        nffs = len(vo_configuration["bigdata_filefamilies"])
        ds_hash = hashlib.sha1(entity.encode("utf-8")).hexdigest()
        ff_index = int(ds_hash[:2], 16) % nffs
        return vo_configuration["bigdata_filefamilies"][ff_index]
    else:
        # Using filenames as entities in case of test VO
        if vo_configuration["VO"] == "test":
            ds_hash = hashlib.sha1(entity.encode("utf-8")).hexdigest()
            ff_number = int(ds_hash[:2], 16) % 8
            data_list = vo_configuration["lfn_data_paths"]
            if any([i in entity for i in data_list]):
                return 991 + ff_number
            else:
                return -1
            return ff_number
        elif vo_configuration["VO"] == "atlas":
            ff_dict = {
                "data": {
                    "/AOD": [810, 811],
                    "/DAOD": [812],
                    "/RAW": [813, 814, 815],
                    "/DRAW": [816],
                    "/DESDM": [817],
                    "/ESD": [818],
                    "REST": [819],
                },
                "mc": {
                    "/AOD": [830, 831, 832, 833],
                    "/DAOD": [834],
                    "/DESDM": [835],
                    "/HITS": [836, 837, 838, 839],
                    "/EVNT": [840],
                    "/ESD": [841],
                    "REST": [842],
                },
                "user": {
                    "DAOD": [852],
                    "REST": [853],
                },
            }
            data_list = vo_configuration["lfn_data_paths"]
            mc_list = vo_configuration["lfn_mc_paths"]
            ff_number = -1
            ds_hash_number = int(
                hashlib.sha1(entity.encode("utf-8")).hexdigest()[:2], 16
            )
            datatype = None
            if "/user" in entity or "atlaslocalgrouptape/hc_test" in entity:
                datatype = "user"
            elif any([subpath in entity for subpath in mc_list]):
                datatype = "mc"
            elif any([subpath in entity for subpath in data_list]):
                datatype = "data"
            # Check if main data type is properly determined
            if datatype:
                found_datatier = False
                for datatier in ff_dict[datatype]:
                    if datatier == "REST":
                        continue
                    if datatier in entity:
                        found_datatier = True
                        if len(ff_dict[datatype][datatier]) == 1:
                            ff_number = ff_dict[datatype][datatier][0]
                        else:
                            index = ds_hash_number % len(ff_dict[datatype][datatier])
                            ff_number = ff_dict[datatype][datatier][index]
                        break
                # Catch case, when none of the main datatiers is matching
                if not found_datatier:
                    datatier = "REST"
                    if len(ff_dict[datatype][datatier]) == 1:
                        ff_number = ff_dict[datatype][datatier][0]
                    else:
                        index = ds_hash_number % len(ff_dict[datatype][datatier])
                        ff_number = ff_dict[datatype][datatier][index]
            return ff_number
