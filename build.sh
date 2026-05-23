#!/bin/bash
source ~/.zshrc;cd /Users/zhuguojun/Documents/git_project/Encrypted_Management && mvn clean package -Denforcer.skip=true -DskipTests -Dspotbugs.skip=true