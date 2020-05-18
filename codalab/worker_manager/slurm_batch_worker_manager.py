import argparse
import boto3
import logging
import os
import uuid
from .worker_manager import WorkerManager, WorkerJob
from pathlib import Path
import subprocess

logger = logging.getLogger(__name__)


class SlurmBatchWorkerManager(WorkerManager):
    NAME = 'slurm-batch'
    DESCRIPTION = 'Worker manager for submitting jobs using Slurm Batch'

    SBATCH_COMMAND = 'sbatch'
    SBATCH_PREFIX = '#SBATCH'
    SRUN_COMMAND_UNBUFFERED = 'srun --unbuffered'

    @staticmethod
    def add_arguments_to_subparser(subparser):
        subparser.add_argument(
            '--job-definition-name',
            type=str,
            default='codalab-slurm-worker',
            help='Name for the job definitions that will be generated by this worker manager',
        )
        subparser.add_argument(
            '--nodelist', type=str, default='', help='The worker node to run jobs in'
        )
        subparser.add_argument(
            '--partition', type=str, default='jag-standard', help='Name of batch job queue to use'
        )
        subparser.add_argument(
            '--cpus', type=int, default=1, help='Default number of CPUs for each worker'
        )
        subparser.add_argument(
            '--gpus', type=int, default=1, help='Default number of GPUs for each worker'
        )
        subparser.add_argument(
            '--memory-mb', type=int, default=2048, help='Default memory (in MB) for each worker'
        )

    def __init__(self, args):
        super().__init__(args)
        self.batch_client = boto3.client('batch', region_name=self.args.region)

    def get_worker_jobs(self):
        """Return list of workers."""
        return NotImplemented

    def start_worker_job(self):
        image = 'codalab/worker:' + os.environ.get('CODALAB_VERSION', 'latest')
        worker_id = uuid.uuid4().hex
        # user's home directory
        work_dir = os.path.join(str(Path.home()), "slurm-worker-scratch/{}".format(worker_id))
        logger.debug('Starting worker %s with image %s', worker_id, image)

        # This needs to be a unique directory since Batch jobs may share a host
        worker_network_prefix = 'cl_worker_{}_network'.format(worker_id)
        command = [
            'cl-worker',
            '--server',
            self.args.server,
            '--verbose',
            '--exit-when-idle',
            '--idle-seconds',
            str(self.args.worker_idle_seconds),
            '--work-dir',
            work_dir,
            '--id',
            worker_id,
            '--network-prefix',
            worker_network_prefix,
            # always set in Slurm worker manager to ensure safe shut down
            '--pass-down-termination',
        ]
        if self.args.worker_tag:
            command.extend(['--tag', self.args.worker_tag])

        sbatch_script = self.create_job_definition(
            slurm_args=self.map_codalab_args_to_slurm_args(self.args), command=command
        )
        self.save_job_definition(os.path.join(work_dir, self.args.job_definition_name), sbatch_script)
        ret = subprocess.call([self.SBATCH_COMMAND, sbatch_script])



    def save_job_definition(self, filename, sbatch_script_contents):
        with open(filename, 'a') as f:
            f.write(sbatch_script_contents)
        logger.info("Saved config file to {}".format(filename))

    def create_job_definition(self, slurm_args, command):
        sbatch_args = [
            '{} --{}={}'.format(self.SBATCH_PREFIX, key, slurm_args[key])
            for key in sorted(slurm_args.keys())
        ]
        sbatch_script = (
            '#!/bin/bash\n\n'
            + '\n'.join(sbatch_args)
            + '\n'
            + self.SRUN_COMMAND_UNBUFFERED
            + ' '.join(command)
        )
        print(sbatch_script)
        return sbatch_script

    def map_codalab_args_to_slurm_args(self, args):
        slurm_args = {}
        slurm_args['nodelist'] = args.nodelist
        slurm_args['mem-per-cpu'] = args.memory_mb
        slurm_args['partition'] = args.partition
        slurm_args['gres'] = "gpu:" + str(args.gpus)
        slurm_args['job-name'] = args.job_definition_name
        slurm_args['cpus-per-task'] = 3
        slurm_args['ntasks-per-node'] = 1
        slurm_args['time'] = '10-0'
        slurm_args["open-mode"] = 'append'
        slurm_args['export'] = 'ANACONDA_ENV=py-3.6.8,ALL'
        return slurm_args
