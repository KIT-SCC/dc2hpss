# dc2hpss
Python script developed against the dCache HSM script interface (https://www.dcache.org/manuals/Book-8.2/config-hsm.shtml).

The version of the script provided in this repository is a demo version of what is used at GridKa in production.
Differences are in the configuration of the script, and in the way the HPSS file families are computed.
The logic of the script remained the same.

## Example commands for testing

This section demonstrates a few minimal examples, how dCache would call the script to interact with HPSS.
The examples would work, provided that all paths and settings in the configuration files `script_configuration.yaml`
and `vo_configuration/test.yaml` are set correctly.

### Command to write a file to HPSS

```bash
./dc2hpss.py put F04C59FC1F5D684B86F0949AF11E1CB8D72F \
  in/F04C59FC1F5D684B86F0949AF11E1CB8D72F \
  -si="hsm=osm;flag-c=1:070d9713;path=/pnfs/path/to/test/data/3GB_files/414cef4f-63ff-4dcd-b8f7-33efec3e09ae.file;store=dc_test;"
```
### Command to recall a file from HPSS

```bash
./dc2hpss.py get F04C59FC1F5D684B86F0949AF11E1CB8D72F \
  out/F04C59FC1F5D684B86F0949AF11E1CB8D72F \
  -si="hsm=osm;flag-c=1:070d9713;path=/pnfs/path/to/test/data/3GB_files/414cef4f-63ff-4dcd-b8f7-33efec3e09ae.file;store=dc_test;" \
  -uri="osm://hpss/TEST/data/3GB_files/414cef4f-63ff-4dcd-b8f7-33efec3e09ae.file?pnfsid=F04C59FC1F5D684B86F0949AF11E1CB8D72F"
```
### Command to delete a file from HPSS

```bash
./dc2hpss.py remove \
  -uri="osm://hpss/TEST/data/3GB_files/414cef4f-63ff-4dcd-b8f7-33efec3e09ae.file?pnfsid=F04C59FC1F5D684B86F0949AF11E1CB8D72F"
```
