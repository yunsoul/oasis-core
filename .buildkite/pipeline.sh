#!/bin/bash
##
# Dynamic Buildkite pipeline generator.
##
#
# It outputs valid Buildkite pipeline in YAML format.
#
# To use it, define the following Steps under your Buildkite's Pipeline Settings:
#
# steps:
#   - command: .buildkite/pipeline.sh | buildkite-agent pipeline upload
#     label: ":pipeline: Upload"
#
# For more details, see:
# https://buildkite.com/docs/pipelines/defining-steps#dynamic-pipelines.
#

set -eux

export DOCKER_OASIS_CORE_CI_BASE_TAG=master

# Decide which pipeline to use.
pipeline=.buildkite/code.pipeline.yml

# Upload the selected pipeline.
cat $pipeline | buildkite-agent pipeline upload
