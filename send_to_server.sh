HOST='db.misc.iastate.edu'
#HOST='10.24.226.58'
USER='me'
TARGETFOLDER='/media/dumps/dumps/new_data'
SOURCEFOLDER='/media/'
rsync -avz $SOURCEFOLDER $USER@$HOST:$TARGETFOLDER > /proc/1/fd/1 2>/proc/1/fd/2
