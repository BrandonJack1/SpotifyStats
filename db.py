import boto3

if __name__ == '__main__':
    dynamodb = boto3.resource('dynamodb', aws_access_key_id='ASIA3TN67ELM77ALY3VN', aws_secret_access_key='hOwmQMvdYW7wXx8OOb8w9LnK/d/4pvZFaLdV4GdW', aws_session_token='FwoGZXIvYXdzEAYaDJSkMmM2jTVfgqtWIyLAASh8b7PeQIZQJxccIlfYHAgBHTE7WxmKG3XxhLqk09UFCFnO42azqKylNiTh6eWaYizXdAv4wa5x6EK/uGuJVhtL5X1CCfuZy8cpp7+bfIlHdusTydIyz12ywWKzjXne59fGj50TUlmUrlGVFHs3wEKCL8C/RZpEI4u0FOVMA9kXs1CgErnF4IJ4Mf0e4ry7FZOVAXSYoPp5hW9AdRPbFhhEdKGssBsaN/sUUPwUogdUtA3/GMPn63p/lVeWjirLDSie9NulBjItERREtaAy//CWnz8jJrYV8GOqJrqiKC5qjbwHMQPVL+OilcgHNvz+t8wg2+zW')

    table = dynamodb.Table('users')




    table = dynamodb.create_table(
        TableName='users',
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