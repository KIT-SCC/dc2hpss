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
