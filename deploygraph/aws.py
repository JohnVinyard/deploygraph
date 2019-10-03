from .requirement import Requirement, retry
from collections import namedtuple
import boto3
import fabric
import requests
from botocore.exceptions import ClientError
import os
import glob
import fnmatch
from requests.exceptions import Timeout, ConnectionError, SSLError
from http import client
from io import StringIO

IngressRule = namedtuple('IngressRule', ['protocol', 'port', 'source'])


class NamedStringIO(StringIO):
    def __init__(self, name, contents=''):
        super().__init__(contents)
        self.name = name


class BaseSecurityGroup(Requirement):
    def __init__(self, group_name, description, vpc_id, *rules):

        # in cases where the source parameter of the ingress rule is another
        # security group, ensure that those are treated as preqrequisites by
        # passing them to the base constructor
        self.vpc_id = vpc_id
        security_group_requirements = filter(
            lambda rule: isinstance(rule, BaseSecurityGroup), rules)
        super(BaseSecurityGroup, self).__init__(*security_group_requirements)
        self.description = description
        self.group_name = group_name
        self.rules = rules
        self.client = boto3.client('ec2')

    def _get_group(self):
        results = self.client.describe_security_groups(Filters=[
            {
                'Name': 'group-name',
                'Values': [self.group_name, ]
            }
        ])
        groups = results['SecurityGroups']
        return groups[0]

    def fulfilled(self):
        try:
            self._get_group()
            return True
        except IndexError:
            return False

    def data(self):
        group = self._get_group()
        return {
            'group_id': group['GroupId'],
            'group_name': group['GroupName']
        }

    def fulfill(self):
        group = self.client.create_security_group(
            Description=self.description,
            GroupName=self.group_name,
            VpcId=self.vpc_id)
        group_id = group['GroupId']

        # Authorize ingress from self
        self.client.authorize_security_group_ingress(
            GroupId=group_id,
            SourceSecurityGroupName=self.group_name
        )

        for rule in self.rules:
            if isinstance(rule, BaseSecurityGroup):
                from_group = rule.data()['group_name']
                self.client.authorize_security_group_ingress(
                    GroupId=group_id,
                    SourceSecurityGroupName=from_group)
            else:
                protocol, port, source = rule
                self.client.authorize_security_group_ingress(
                    CidrIp=source,
                    FromPort=port,
                    ToPort=port,
                    GroupId=group_id,
                    IpProtocol=protocol)


class PublicInternetSecurityGroup(BaseSecurityGroup):
    def __init__(self):
        super(PublicInternetSecurityGroup, self).__init__(
            'public-internet',
            'public-facing servers',
            IngressRule(protocol='tcp', port=22, source='0.0.0.0/0'),
            IngressRule(protocol='tcp', port=80, source='0.0.0.0/0'),
            IngressRule(protocol='tcp', port=443, source='0.0.0.0/0'))


class InternalServiceSecurityGroup(BaseSecurityGroup):
    def __init__(self, public_internet_security_group):
        super(InternalServiceSecurityGroup, self).__init__(
            'internal-service',
            'internal service',
            public_internet_security_group,
            IngressRule(protocol='tcp', port=22, source='0.0.0.0/0'))


class S3Bucket(Requirement):
    def __init__(self, bucket_name, region):
        super(S3Bucket, self).__init__()
        self.region = region
        self.bucket_name = bucket_name
        self.client = boto3.client('s3')

    @property
    def name(self):
        return self.bucket_name

    @property
    def hostname(self):
        return 'https://s3-{region}.amazonaws.com'.format(region=self.region)

    def data(self):
        return {
            'hostname': self.hostname,
            'bucket': self.bucket_name,
            'endpoint': '{hostname}/{bucket}'.format(
                hostname=self.hostname, bucket=self.bucket_name)
        }

    def fulfilled(self):
        try:
            self.client.head_bucket(Bucket=self.bucket_name)
            return True
        except ClientError:
            return False

    def fulfill(self):
        self.client.create_bucket(
            ACL='public-read',
            Bucket=self.bucket_name,
            CreateBucketConfiguration={
                'LocationConstraint': self.region
            })


class CorsConfig(Requirement):
    def __init__(self, bucket):
        super(CorsConfig, self).__init__(bucket)
        self.bucket = bucket
        self.client = boto3.client('s3')

    def fulfilled(self):
        try:
            self.client.get_bucket_cors(Bucket=self.bucket.name)
            return True
        except ClientError:
            return False

    def data(self):
        return self.bucket.data()

    def fulfill(self):
        self.client.put_bucket_cors(
            Bucket=self.bucket.name,
            CORSConfiguration={
                'CORSRules': [
                    {
                        'AllowedMethods': ['GET'],
                        'AllowedOrigins': ['*'],
                        'MaxAgeSeconds': 3000
                    }
                ]
            }
        )


class ServiceLinkedRole(Requirement):
    def __init__(self, service_name, description):
        super(ServiceLinkedRole, self).__init__()
        self.service_name = service_name
        self.client = boto3.client('iam')
        self.expected_path = \
            '/aws-service-role/{service_name}/'.format(
                service_name=service_name)
        self.description = description

    def _get_data(self):
        roles = self.client.list_roles()['Roles']
        role = filter(lambda role: role['Path'] == self.expected_path, roles)[0]
        return role

    def fulfilled(self):
        try:
            self._get_data()
            return True
        except IndexError:
            return False

    def fulfill(self):
        self.client.create_service_linked_role(
            AWSServiceName=self.service_name,
            Description=self.description)

    def data(self):
        return self._get_data()


class Connection(fabric.Connection):
    def __init__(self, ip, pem_path):
        super(Connection, self).__init__(ip, user='ubuntu', connect_kwargs={
            'key_filename': pem_path
        })

    def append_line(self, text, path):
        self.sudo(f'echo "{text}" | sudo tee -a {path}')

    def sudo_put(self, local_path, remote_path):
        tmp = '/tmp'
        self.put(local_path, tmp)
        try:
            _, filename = os.path.split(local_path)
        except TypeError:
            filename = local_path.name
        temp_path = os.path.join(tmp, filename)
        self.sudo(f'sudo mv {temp_path} {remote_path}')

    def copy_glob(self, pattern, destination, *excluded_patterns):
        for f in glob.glob(pattern):
            if any(fnmatch.fnmatch(f, pat) for pat in excluded_patterns):
                print(f'skipped {f}')
                continue
            self.put(f, destination)
            print(f'copied {f} to {destination}')

    @retry(10, delay=2)
    def test(self):
        return self.run('ls')


class Box(Requirement):
    def __init__(self, instance_name, image_id, instance_type, security_group):
        super(Box, self).__init__(security_group)
        self.resource = boto3.resource('ec2')
        self.client = boto3.client('ec2')
        self.instance_type = instance_type
        self.image_id = image_id
        self.instance_name = instance_name
        self.pem_path = 'aws-certs/{instance_name}.pem'.format(**self.__dict__)
        self.security_group = security_group

    def _get_instance(self, states=['running', 'pending']):
        instances = self.client.describe_instances(Filters=[
            {
                'Name': 'tag:Name',
                'Values': [self.instance_name]
            },
            {
                'Name': 'instance-state-name',
                'Values': states
            }
        ])
        return instances['Reservations'][0]['Instances'][0]

    def fulfilled(self):
        try:
            self._get_instance()
            return True
        except IndexError:
            return False

    @retry(tries=20, delay=2)
    def data(self):
        instance = self._get_instance()
        return {
            'PublicIpAddress': instance['PublicIpAddress'],
            'PublicDnsName': instance['PublicDnsName'],
            'internal_ip': instance['PrivateIpAddress'],
            'internal_hostname': instance['PrivateDnsName'],
            'pem_path': self.pem_path
        }

    def connection(self):
        data = self.data()
        ip = data['PublicIpAddress']
        pem_path = data['pem_path']
        connection = Connection(ip, pem_path)
        connection.test()
        return connection

    def fulfill(self):
        try:
            key_pair = self.client.create_key_pair(KeyName=self.instance_name)
            with open(self.pem_path, 'w') as f:
                f.write(key_pair['KeyMaterial'])
        except ClientError:
            # the key has already been created
            pass
        os.chmod(self.pem_path, 0o600)

        security_group_id = self.security_group.data()['group_id']
        self.resource.create_instances(
            ImageId=self.image_id,
            InstanceType=self.instance_type,
            MinCount=1,
            MaxCount=1,
            KeyName=self.instance_name,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': self.instance_name}
                    ]
                }
            ],
            SecurityGroupIds=[security_group_id, ]
        )
        connection = self.connection()
        connection.sudo('apt-get update --fix-missing')
        connection.sudo('apt-get install -y httping')


class BaseServer(Requirement):
    def __init__(self, box, config):
        super(BaseServer, self).__init__(box, config)
        self.config = config
        self.box = box

    def connection(self):
        return self.box.connection()

    def apt_update(self, connection):
        connection.sudo('apt-get update --fix-missing')

    def apt_install(self, connection, *packages):
        packages = ' '.join(packages)
        connection.sudo('apt-get install -y {packages}'.format(**locals()))

    def pip_install(self, connection, *packages):
        packages = ' '.join(packages)
        connection.run(
            'pip --no-cache-dir install {packages}'.format(**locals()))


class AnacondaServer(BaseServer):
    def __init__(self, box, config, conda_env):
        super(AnacondaServer, self).__init__(box, config)
        self.conda_env = conda_env

    def _inner_fulfill(self, connection):
        raise NotImplementedError()

    def _conda_env(self, connection):
        return connection.prefix(
            'source conda/bin/activate {env}'.format(env=self.conda_env))

    @property
    def conda_env_path(self):
        return '/home/ubuntu/conda/envs/{env}'.format(
            env=self.conda_env)

    @property
    def conda_env_lib_path(self):
        return os.path.join(self.conda_env_path, 'lib')

    @property
    def conda_env_bin_path(self):
        return os.path.join(self.conda_env_path, 'bin')

    @property
    def conda_env_python(self):
        return os.path.join(self.conda_env_bin_path, 'python')

    def run_from_conda_bin(self, connection, command, args):
        path = os.path.join(self.conda_env_bin_path, command)
        connection.run('{path} {args}'.format(**locals()))

    def conda_install(self, connection, packages, channels):
        channels = ' '.join(['-c {c}'.format(c=c) for c in channels])
        packages = ' '.join(packages)
        with self._conda_env(connection):
            connection.run(
                'conda/bin/conda install -y {channels} {packages}'
                    .format(**locals()))
            connection.run('conda/bin/conda clean -i -l -t -y')

    def fulfill(self):
        connection = self.connection()
        self.apt_update(connection)
        self.apt_install(connection, 'wget', 'bzip2', 'python', 'gcc')

        connection.sudo('touch /etc/profile.d/conda.sh')
        connection.append_line(
            'export PATH=/home/ubuntu/conda/bin:$PATH',
            '/etc/profile.d/conda.sh')

        miniconda_filename = 'Miniconda3-latest-Linux-x86_64.sh'

        connection.run(
            f'wget https://repo.anaconda.com/miniconda/{miniconda_filename}')
        connection.run(
            f'/bin/bash {miniconda_filename} -b -p /home/ubuntu/conda',
            warn=True)
        connection.run(f'rm {miniconda_filename}', warn=True)

        connection.run(
            'conda/bin/conda create -y -n {env} python=3.7'.format(
                env=self.conda_env), warn=True)

        self.conda_install(
            connection,
            packages=('numpy==1.15.3', 'scipy=1.1.0'),
            channels=('hcc', 'conda-forge'))

        self._inner_fulfill(connection)


class SupervisordHelper(object):
    def __init__(
            self,
            app_name,
            local_path,
            remote_path,
            config_filename='supervisord.conf',
            remote_log_path='/home/ubuntu/supervisord'):
        super(SupervisordHelper, self).__init__()
        self.remote_log_path = remote_log_path
        self.config_filename = config_filename
        self.local_path = local_path
        self.remote_path = remote_path
        self.app_name = app_name

    @property
    def conf_path(self):
        return os.path.join(self.remote_path, self.config_filename)

    @property
    def local_conf_path(self):
        return os.path.join(self.local_path, self.config_filename)

    def check_running(self, connection):
        """
        Succeed silently, or raise if not running
        """
        connection.run(
            'supervisorctl -c {path} pid {app_name}'
                .format(path=self.conf_path, app_name=self.app_name))

    def copy_config(self, connection, variables=None):
        if variables:
            with open(self.local_conf_path, 'r') as f:
                content = f.read()
                with_variables = content.format(**variables)
                sio = NamedStringIO(self.config_filename, with_variables)
                connection.put(sio, self.remote_path)
        else:
            connection.copy_glob(self.local_conf_path, self.remote_path)

    def make_remote_log_directory(self, connection):
        connection.run('mkdir -p {path}'.format(path=self.remote_log_path))

    def prepare(self, connection, variables=None):
        self.copy_config(connection, variables=variables)
        self.make_remote_log_directory(connection)

    def start(self, connection):
        connection.run('kill -s SIGTERM $(cat supervisord.pid)', warn=True)
        try:
            connection.run(
                'supervisord -c {path}'.format(path=self.conf_path))
        except:
            self.restart(connection)

    def restart(self, connection):
        connection.run(
            'supervisorctl -c {path} stop all'
                .format(path=self.conf_path))
        connection.run(
            'supervisorctl -c {path} start all'
                .format(path=self.conf_path))


# class FeatureExtractorApp(Requirement):
#     def __init__(self, server):
#         super(FeatureExtractorApp, self).__init__(server)
#         self.server = server
#
#     def fulfilled(self):
#         raise AlwaysUpdateException()
#
#     def data(self):
#         return self.server.data()
#
#     @property
#     def supervisord(self):
#         return self.server.supervisord
#
#     def _conda_env(self, connection):
#         return self.server._conda_env(connection)
#
#     def fulfill(self):
#         connection = self.server.connection()
#         connection.copy_glob('deploy/featureextractor/*.py', 'remote/')
#         connection.copy_glob('deploy/featureextractor/*.dat', 'remote/')
#
#         self.supervisord.copy_config(connection)
#
#         with self._conda_env(connection):
#             self.supervisord.restart(connection)
#
#
# class SimilarityIndexApp(Requirement):
#     def __init__(self, server):
#         super(SimilarityIndexApp, self).__init__(server)
#         self.server = server
#
#     def fulfilled(self):
#         raise AlwaysUpdateException()
#
#     def data(self):
#         return self.server.data()
#
#     def _conda_env(self, connection):
#         return self.server._conda_env(connection)
#
#     @property
#     def port(self):
#         return self.server.port
#
#     @property
#     def supervisord(self):
#         return self.server.supervisord
#
#     def fulfill(self):
#         connection = self.server.connection()
#         connection.copy_glob('deploy/similarityindex/*', 'remote/', '*.pyc')
#         self.supervisord.copy_config(connection)
#         with self._conda_env(connection):
#             self.supervisord.restart(connection)
#
#
# class CochleaServer(BaseServer):
#     def __init__(self, box, config):
#         super(CochleaServer, self).__init__(box, config)
#         self.supervisord = SupervisordHelper(
#             'app',
#             'deploy/app',
#             'remote/')
#
#     def fulfilled(self):
#         """
#         Check that the about page returns a 200
#         """
#         data = self.box.data()
#         ip = data['PublicIpAddress']
#         try:
#             # the app will only be accessible via an insecure connection
#             # before TLS is setup
#             resp = requests.get(
#                 'http://{ip}/about'.format(**locals()))
#             resp.raise_for_status()
#             return True
#         except (ConnectionError, Timeout, HTTPError):
#             pass
#
#         try:
#             # once DNS is setup, the app will be accessible by domain name
#             # via an insecure connection.  Once TLS is setup, the insecure
#             # connection will redirect to HTTPS
#             resp = requests.get(
#                 'https://{domain}/about'.format(domain=DOMAIN))
#         except (ConnectionError, SSLError, Timeout):
#             return False
#
#         return resp.status_code == httplib.OK
#
#     def data(self):
#         d = self.box.data()
#         d.update(supervisord_helper=self.supervisord)
#         return d
#
#     def fulfill(self):
#         connection = self.connection()
#         # connection.sudo('apt-get update --fix-missing')
#         self.apt_update(connection)
#
#         # nginx setup
#         connection.sudo('wget http://nginx.org/keys/nginx_signing.key')
#         connection.sudo('apt-key add nginx_signing.key')
#
#         connection.append_line(
#             'deb http://nginx.org/packages/ubuntu xenial nginx',
#             '/etc/apt/sources.list')
#         connection.append_line(
#             'deb-src http://nginx.org/packages/ubuntu xenial nginx',
#             '/etc/apt/sources.list')
#
#         self.apt_install(connection, 'nginx')
#         connection.run('mkdir -p remote/static')
#         connection.sudo_put('deploy/nginx/nginx.conf', '/etc/nginx')
#         connection.copy_glob('deploy/nginx/static/*', 'remote/static')
#
#         # app
#         self.apt_install(connection, 'curl', 'python')
#
#         connection.run(
#             'curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py')
#         connection.sudo('python get-pip.py')
#
#         connection.sudo('pip install virtualenv')
#         connection.run('virtualenv cochlea', warn=True)
#         connection.copy_glob('deploy/app/*', 'remote/', '*.pyc')
#
#         self.supervisord.prepare(connection)
#
#         with connection.prefix('source cochlea/bin/activate'):
#             self.pip_install(
#                 connection,
#                 'falcon',
#                 'gunicorn',
#                 'redis',
#                 'boto3',
#                 'elasticsearch',
#                 'pytz',
#                 'requests',
#                 'supervisor')
#             self.supervisord.start(connection)
#
#         # nginx start
#         connection.sudo('nginx -t -c /etc/nginx/nginx.conf')
#         connection.sudo('service nginx start')
#         connection.sudo('service nginx reload')
#
#
# class CochleaApp(Requirement):
#     def __init__(self, server, feature_extractor):
#         super(CochleaApp, self).__init__(server, feature_extractor)
#         self.server = server
#         self.feature_extractor = feature_extractor
#
#     def data(self):
#         return self.server.data()
#
#     def connection(self):
#         return self.server.connection()
#
#     @property
#     def supervisord(self):
#         return self.server.supervisord
#
#     def fulfilled(self):
#         raise AlwaysUpdateException()
#
#     def fulfill(self):
#         connection = self.server.connection()
#         connection.copy_glob('deploy/nginx/static/*', 'remote/static')
#         connection.copy_glob('deploy/app/*', 'remote/', '*.pyc')
#         self.supervisord.copy_config(connection)
#         with connection.prefix('source cochlea/bin/activate'):
#             self.supervisord.restart(connection)
#         connection.sudo('service nginx reload')


class DNS(Requirement):
    def __init__(self, app, domain_name, add_www=True):
        super(DNS, self).__init__(app)
        self.add_www = add_www
        self.domain_name = domain_name
        self.app = app
        self.client = boto3.client('route53')

    def connection(self):
        return self.app.connection()

    def fulfilled(self):
        try:
            requests.get(f'http://{self.domain_name}', timeout=10)
            return True
        except (Timeout, ConnectionError):
            return False

    def data(self):
        data = self.app.data()
        data.update(domain=self.domain_name)
        return data

    def _change_template(self, domain_name, ip):
        return {
            'Action': 'UPSERT',
            'ResourceRecordSet': {
                'Name': domain_name,
                'Type': 'A',
                'TTL': 300,
                'ResourceRecords': [
                    {
                        'Value': ip
                    },
                ],
            }
        }

    def fulfill(self):
        ip = self.app.data()['PublicIpAddress']

        zones = self.client.list_hosted_zones()['HostedZones']
        zones = filter(lambda z: z['Name'] == 'cochlea.xyz.', zones)

        for zone in zones:
            changes = [self._change_template(self.domain_name, ip)]
            if self.add_www:
                changes.append(
                    self._change_template(f'www.{self.domain_name}', ip))

            zone_path = zone['Id']
            self.client.change_resource_record_sets(
                HostedZoneId=zone_path,
                ChangeBatch={
                    "Comment": "Automatic DNS update",
                    "Changes": changes
                }
            )


# TODO: Make www domain optional
class TLS(Requirement):
    def __init__(self, dns, email_address, add_www=True):
        super(TLS, self).__init__(dns)
        self.add_www = add_www
        self.dns = dns
        self.email_address = email_address

    def fulfilled(self):
        domain = self.dns.data()['domain']
        try:
            resp = requests.get('https://{domain}'.format(**locals()))
            return resp.status_code == client.OK
        except (ConnectionError, Timeout, SSLError) as e:
            print('TLS FAILED', e)
            return False

    def data(self):
        return dict()

    def fulfill(self):
        connection = self.dns.connection()
        data = self.dns.data()
        connection.sudo('add-apt-repository ppa:certbot/certbot -y')
        connection.sudo('apt-get update -y')
        connection.sudo('apt-get install python-certbot-nginx -y')
        domain = data['domain']

        email = self.email_address
        cmd = f'certbot \
                --nginx \
                -d {domain} \
                -n \
                --redirect \
                --agree-tos \
                -m {email}'

        if self.add_www:
            www_domain = 'www.{domain}'.format(**locals())
            cmd += f' -d {www_domain}'

        connection.sudo(cmd)


class Deployment(object):
    def __init__(self, *requirements):
        super(Deployment, self).__init__()
        self.requirements = requirements

    def deploy(self):
        for requirement in self.requirements:
            requirement()
