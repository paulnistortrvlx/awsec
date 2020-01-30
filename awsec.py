#!/usr/bin/env python

import boto3
import json
import os
import time


cf = boto3.client('cloudfront')
s3 = boto3.client('s3')
cfg = boto3.client('config')
r53 = boto3.client('route53')
wafcl = boto3.client('waf')
ec2 = boto3.client('ec2')
rds = boto3.client('rds')
gd = boto3.client('guardduty')
kms = boto3.client('kms')


def s3_origins():
    '''
    return origins of cloudfront distributions
    '''

    s3orgs = []
    r = cf.list_distributions()
    try:
        dists = r['DistributionList']['Items']
        for dist in dists:
            for item in dist['Origins']['Items']:
                if 'S3OriginConfig' in item.keys():
                    s3orgs.append(item['DomainName'].replace(
                        '.s3.amazonaws.com', ''))
        return s3orgs
    except Exception:
        return []


def empty_buckets(buckets):
    '''
    takes a list of buckets as argument and return a list of empty buckets
    '''

    ret = []
    for bucket in buckets:
        try:
            rs3 = s3.list_objects(
                Bucket=bucket
            )
            if 'Contents' not in rs3.keys():
                ret.append(bucket)
        except Exception:
            print(f'Access denied on {bucket}')
    return ret


def eval_results(rule):
    '''
    takes an AWSConfig rule and return list of findings for it
    '''

    ret = []
    r = cfg.get_compliance_details_by_config_rule(
        ConfigRuleName=rule,
        ComplianceTypes=['NON_COMPLIANT'],
        Limit=100
    )
    for rez in r['EvaluationResults']:
        ret.append(rez['EvaluationResultIdentifier']
                   ['EvaluationResultQualifier']['ResourceId'])
    return ret


def cf_distributions():
    '''
    return a dictionary with distribution ID as key and the value is a list
    with LoggingEnabled value and the origin
    '''

    rq = cf.list_distributions()
    dist_list = []
    ret = {}
    try:
        dist_list_ids = rq['DistributionList']['Items']
        for item in dist_list_ids:
            dist_list.append(item['Id'])
        for dist in dist_list:
            drq = cf.get_distribution(Id=dist)
            en = drq['Distribution']['DistributionConfig']['Logging']['Enabled']
            try:
                info = drq['Distribution']['DistributionConfig']['Aliases']['Items'][0]
            except Exception:
                info = drq['Distribution']['DistributionConfig']['Origins']['Items'][0]['DomainName']
            ret.update({dist: [en, info]})
        return ret
    except Exception:
        return {}


def cloudfront_audit():
    '''
    Display the distributions without logging enabled
    '''

    dists = cf_distributions()
    print(dists)
    for id, info in dists.items():
        if not info[0]:
            print(f'{id} : {info[1]}')


# example of cloudfront distribution update function
# def dist_update(id):
#     rq_old = cf.get_distribution_config(Id=id)
#     try:
#         dn = rq_old['DistributionConfig']['Aliases']['Items'][0]
#     except:
#         dn = rq_old['DistributionConfig']['Origins']['Items'][0]['DomainName']
#     print(dn)
#     ifmatch = rq_old['ResponseMetadata']['HTTPHeaders']['etag']
#     logging = rq_old['DistributionConfig']['Logging']['Enabled']
#     print(logging)
#     rq_old['DistributionConfig']['Logging'] = {
#         'Enabled': True,
#         'IncludeCookies': False,
#         'Bucket': 'bucketName',
#         'Prefix': 'prefix'
#     }
#     rq_new = cf.update_distribution(
#         DistributionConfig=rq_old['DistributionConfig'],
#         Id=id,
#         IfMatch=ifmatch
#     )
#     print(rq_old)


def s3_public_access():
    '''
    Display the buckets with public access permited from
    AWSConfig findings by category: CloudFront buckets, 
    nonCloudFront buckets and empty buckets
    '''

    s3orgs = s3_origins()
    all_nc = eval_results('s3-bucket-public-read-prohibited')
    cf_buckets = []
    noncf_buckets = []

    for item in all_nc:
        if item in s3orgs:
            cf_buckets.append(item)
        else:
            noncf_buckets.append(item)

    print('CF buckets')
    for bk in cf_buckets:
        print(bk)
    print('\nNon CF buckets')
    for bk in noncf_buckets:
        print(bk)
    print('\nEmpty buckets')
    for eb in empty_buckets(noncf_buckets):
        print(eb)


def s3_audit():
    '''
    Display the Buckets without logging enbled
    and count them
    '''

    ret = []
    rq = s3.list_buckets()
    bucket_list = []
    for bucket in rq['Buckets']:
        bucket_list.append(bucket['Name'])
    rs3 = boto3.resource('s3')
    for bucket in bucket_list:
        r = rs3.BucketLogging(bucket)
        if not r.logging_enabled:
            ret.append(bucket)
            print(f'{bucket} logging {r.logging_enabled}')
    print(len(ret))


def zones():
    '''
    Displays the DNS zones and if the zone has logging enabled
    '''

    r53 = boto3.client('route53')
    rq = r53.list_hosted_zones()
    for zone in rq['HostedZones']:
        zone_id = (zone['Id'].split('/'))[-1]
        zone_name = zone['Name']
        print(f'{zone_id} - {zone_name}')
        try:
            rs = r53.get_query_logging_config(Id=zone_id)
            print(rs)
        except Exception:
            print('No logging config\n')


def waf(urls):
    '''
    takes a list of urls as input and 
    return the WebACL Id of them
    '''

    rq = wafcl.list_web_acls()
    for acl in rq['WebACLs']:
        rq = cf.list_distributions_by_web_acl_id(
            WebACLId=acl['WebACLId'])
        try:
            for item in rq['DistributionList']['Items']:
                for url in urls:
                    if url in item['Aliases']['Items']:
                        print(acl['WebACLId'])
        except Exception:
            pass


def volumes():
    '''
    Return a list of unencrypted volumes
    and display the count
    '''

    ret = []
    vols = ec2.describe_volumes()
    for vol in vols['Volumes']:
        if not vol['Encrypted']:
            ret.append(vol['VolumeId'])
    print(f'{len(ret)} unencrypted volumes')
    un = set(ret)
    print(len(un))
    print(ret) if len(ret) != 0 else ""
    return ret


def snapshots():
    '''
    Return a list of unencrypted snapshots
    and display the count
    '''

    ret = []
    snaps = ec2.describe_snapshots(OwnerIds=['self'])
    for snap in snaps['Snapshots']:
        if not snap['Encrypted']:
            ret.append(snap['SnapshotId'])
    print(f'{len(ret)} unencrypted snapshots')
    print(ret) if len(ret) != 0 else ""
    return ret


def rds_instances():
    '''
    Return a list of DBs with unencrypted storage
    '''

    ret = []
    rq = rds.describe_db_instances()
    for db in rq['DBInstances']:
        if not db['StorageEncrypted']:
            ret.append((db['DBInstanceIdentifier'], db['DbiResourceId']))
    return ret


def all_rds_instances():
    '''
    Return a list of RDS DB instances
    '''

    ret = {}
    rq = rds.describe_db_instances()
    for db in rq['DBInstances']:
        ret.update({db['DbiResourceId']: db['DBInstanceIdentifier']})
        try:
            print(db['DBName'], db['DBInstanceIdentifier'], db['Engine'],
                  db['CACertificateIdentifier'])
        except Exception:
            print(db['DBInstanceIdentifier'], db['Engine'],
                  db['CACertificateIdentifier'])
    return ret


def rds_snapshots():
    '''
    Return a list of unencrypted DB snapshots
    '''

    ret = []
    rq = rds.describe_db_snapshots()
    for db in rq['DBSnapshots']:
        if not db['Encrypted']:
            ret.append((db['DBSnapshotIdentifier'], db['DbiResourceId']))
    return ret


def all_rds_snapshots():
    '''
    Return a list of all DB snapshots
    '''

    ret = []
    rq = rds.describe_db_snapshots()
    for db in rq['DBSnapshots']:
        ret.append((db['DBSnapshotIdentifier'], db['DbiResourceId']))
    return ret


def guard_duty():
    '''
    Display all existing GuardDuty detector resources
    '''

    rq = gd.list_detectors()
    print(rq['DetectorIds'])


def kms_keys():
    '''
    retur a list of all KMS keys
    '''

    ret = []
    rk = kms.list_keys()
    for key in rk['Keys']:
        ret.append(key['KeyId'])
    return ret


def kms_rotation():
    '''
    Display the keys without rotation enabled
    '''

    for key in kms_keys():
        try:
            r = kms.get_key_rotation_status(KeyId=key)
            if not r['KeyRotationEnabled']:
                print(key, r['KeyRotationEnabled'])
        except Exception:
            print(f'{key} read error')


if __name__ == '__main__':
    # s3_public_access()
    # print(cloudfront_audit())
    # assume_role()
    # s3_audit()
    # print('====\nAWSConfig results\n')
    # for res in eval_results('s3-bucket-logging-enabled'):
    #     print(res)
    # print(len(eval_results('s3-bucket-logging-enabled')))
    # for account in ACCOUNTS:
    #     os.system(f'awsume {account}')
    #     print(f'\nRoute53 zones on {account}')
    # snapshots()
    # volumes()
    # print(rds_instances())
    # print(len(rds_snapshots()))
    # for snap in rds_snapshots():
    #     print(snap)
    #
    # List orphan snapshots
    # rds_list = all_rds_instances()
    # snap_list = all_rds_snapshots()
    # for snap in snap_list:
    #     if snap[1] not in rds_list.keys():
    #         print(snap)
    #
    # Get WebACL IDs
    # urls = []
    # waf(urls)
    # print(guard_duty())
    # print(kms_keys())
    # kms_rotation()
    all_rds_instances()
