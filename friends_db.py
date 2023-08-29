import boto3

if __name__ == '__main__':
    dynamodb = boto3.resource('dynamodb',
                              aws_access_key_id='ASIA3TN67ELMVQGO6XFC',
                              aws_secret_access_key='2JCIHbz51MfXxhGTluXONrITHjJLZWs/9+LZexUP',
                              aws_session_token='FwoGZXIvYXdzECAaDDdFli7PpCMtS1yqZyLAAYWyoIMTlOLwZ5wVlzMaBaqeXYiSRSCjp4tYwjQlJsoXyT3xDFCDOyhevE1hotStsI8403++pkJ5+oTFhY+5iIFFgIzzSXEBS75bBkgrRVUJDxpjCBtDZHaoCvzA9BzmUQg1XFSd09ABYuiNpfa7KBmtwv0X0+DT0t6C7FV/n7fWxwR14yPGwz/Uv41JisrXiNkU+c+4l6gPAK005Sx8CIxGQDBANv5BCVROTXuRydcnn/1XaN0F2ngkx2KQnavi6yi15ZmmBjItIEDtAGv+QDS29flX57lEGtBz904+IdBa8zIKvLAXblirGeUxMgEOeQTugPY1'

    )

    table = dynamodb.Table('friends')

    #table.delete()


    table = dynamodb.create_table(
        TableName='friends',
        KeySchema=[
            {
                'AttributeName': 'id',
                'KeyType': 'HASH'
            },
            {
                'AttributeName': 'username',
                'KeyType': 'RANGE'
            }

        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'id',
                'AttributeType': 'S'
            },
            {
                'AttributeName': 'username',
                'AttributeType': 'S'
            },

        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    # Wait until the table exists.
    table.wait_until_exists()

    # Print out some data about the table.
    print(table.item_count)