#!/bin/bash

protoc c2.proto --go_out=plugins=grpc:.
