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

## ATLAS-specific dc2hpss.py calls for writing

This section shows examples for writing ATLAS-specific files to HPSS, making use of extended attributes to determine
the dataset size, and decide on an appropriate strategy for file family computation. The script calls correspond to
original commands set by dCache in the ATLAS setup of GridKa HPSS.

### Writing a file from a small ATLAS dataset

```bash
./dc2hpss.py put 0000479E77A561B14BFB9ECC293B21A4C7DF in/0000479E77A561B14BFB9ECC293B21A4C7DF \
  -si="size=745144440;new=true;stored=false;sClass=dc_atlas:ATLAS-DATA;cClass=-;hsm=osm;accessLatency=NEARLINE;retentionPolicy=CUSTODIAL;xattr.dataset_length=4;writeToken=745824;gid=5300;StoreName=dc_atlas;xattr.dataset_bytes=2820065392;xattr.dataset_name=data23_calib.00459939.calibration_LArElec-LatomeRuns-32s-High-All-DT-RawData.daq.RAW;xattr.xdg.origin.url=https://eosatlas.cern.ch:443/eos/atlas/atlastier0/rucio/data23_calib/calibration_LArElec-LatomeRuns-32s-High-All-DT-RawData/00459939/data23_calib.00459939.calibration_LArElec-LatomeRuns-32s-High-All-DT-RawData.daq.RAW/data23_calib.00459939.calibration_LArElec-LatomeRuns-32s-High-All-DT-RawData.daq.RAW._lb0000._SFO-3._0001.data?copy_mode=pull;flag-c=1:7674b216;path=/pnfs/gridka.de/atlas/atlasdatatape/data23_calib/RAW/other/data23_calib.00459939.calibration_LArElec-LatomeRuns-32s-High-All-DT-RawData.daq.RAW/data23_calib.00459939.calibration_LArElec-LatomeRuns-32s-High-All-DT-RawData.daq.RAW._lb0000._SFO-3._0001.data;uid=11001;SpaceTokenDescription=ATLASDATATAPE;xattr.dataset_scope=data23_calib;links=00004B98D2EBDC2A4333AEB819D7CC671B1C data23_calib.00459939.calibration_LArElec-LatomeRuns-32s-High-All-DT-RawData.daq.RAW._lb0000._SFO-3._0001.data;SpaceToken=745824;LinkGroupId=7;store=dc_atlas;group=ATLAS-DATA;bfid=<Unknown>;"
```

### Writing a file from a big ATLAS dataset

```bash
./dc2hpss.py put 000048E4146762D9438391C5BFB1615B5269 in/000048E4146762D9438391C5BFB1615B5269 \
  -si="size=10276503022;new=true;stored=false;sClass=dc_atlas:ATLAS-DATA;cClass=-;hsm=osm;accessLatency=NEARLINE;retentionPolicy=CUSTODIAL;xattr.dataset_length=4729;writeToken=745824;gid=5300;StoreName=dc_atlas;xattr.dataset_bytes=43630167902656;xattr.dataset_name=data17_5TeV.00341027.physics_Main.merge.AOD.r11215_p3764_tid17366429_00;xattr.xdg.origin.url=https://eosatlas.cern.ch:443/eos/atlas/atlasdatadisk/rucio/data17_5TeV/9e/19/AOD.17366429._000303.pool.root.1?copy_mode=pull;flag-c=1:05ca01e6;path=/pnfs/gridka.de/atlas/atlasdatatape/data17_5TeV/AOD/r11215_p3764/data17_5TeV.00341027.physics_Main.merge.AOD.r11215_p3764_tid17366429_00/AOD.17366429._000303.pool.root.1_1693321992;uid=11001;SpaceTokenDescription=ATLASDATATAPE;xattr.dataset_scope=data17_5TeV;links=000031DE23DA89174F3684EE2DF4FB0C23CB AOD.17366429._000303.pool.root.1_1693321992;SpaceToken=745824;LinkGroupId=7;store=dc_atlas;group=ATLAS-DATA;bfid=<Unknown>;"
```
