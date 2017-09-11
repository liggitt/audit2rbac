#!/bin/bash

root="$(dirname "${BASH_SOURCE}")/.."
vendor_root="${root}/vendor"
notice_file="${root}/NOTICE"

echo "audit2rbac
Copyright 2017 Jordan Liggitt

" > "${notice_file}"

for license in $(find "${vendor_root}" -name LICENSE | sort); do
    # remove prefix
    component=${license#$vendor_root/}
    # remove /LICENSE suffix
    component=${component%/LICENSE}
    # append to NOTICE file
    echo "================================================================================" >> "${notice_file}"
    echo "= ${component} licensed under: ="                                                 >> "${notice_file}"
    echo ""                                                                                 >> "${notice_file}"
    cat $license                                                                            >> "${notice_file}"
    echo ""                                                                                 >> "${notice_file}"
    echo ""                                                                                 >> "${notice_file}"
done
