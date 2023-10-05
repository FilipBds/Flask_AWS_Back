import certifi
import os
import pymongo
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token
from flask_bcrypt import Bcrypt
from bson import json_util, ObjectId
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import make_response
import secrets

# Generate a secure secret key

secret_key = secrets.token_hex(32)
application.config['SECRET_KEY'] = secret_key
application.config['MAIL_SERVER'] = 'smtp.gmail.com'
application.config['MAIL_PORT'] = 587
application.config["MAIL_USERNAME"] = 'bytelinksrl@gmail.com'
application.config["MAIL_PASSWORD"] = 'dyan kyvw cvqs yhf'
application.config['MAIL_USE_TLS'] = True  # Use TLS encryption

mail = Mail(application)

# Set the SSL certificate file location to resolve any SSL certificate issues
os.environ['SSL_CERT_FILE'] = certifi.where()

application = Flask(__name__)
bcrypt = Bcrypt(application)
jwt = JWTManager(application)

# Connect to MongoDB
# Connect to MongoDB
try:
    client = pymongo.MongoClient(
        "mongodb+srv://Mark_Jeff:1234@cluster0.0jh9bwk.mongodb.net/?retryWrites=true&w=majority")
    db = client.get_database('test')
    print("Connected")
    collection = db.users
    collection1 = db.posts
    collection2 = db.notifications
    collection3 = db.private_box

    collections = collection.find()
    print("Connected")

except pymongo.errors.ConnectionFailure as e:
    print("Could not connect to MongoDB: %s" % e)

@application.route('/send_verification_code', methods=['POST'])
def send_verification_code():

    data = request.get_json()
    email = data.get('email')
    user = collection.find_one({'email': email})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Generate a random verification code
    verification_code = ''.join(random.choices(string.digits, k=6))

    # Store the verification code in the database (replace 'verification_code_field' with actual field name)
    collection.update_one({'_id': user['_id']}, {
                          '$set': {'verification_code_field': verification_code}})

    sender = 'noreply@app.com'
    msg = Message('Reset Password Verfication Code',
                  sender=sender, recipients=[email])
    email_body = f"Hello {user['name']},\n\n"
    email_body += "You have requested to reset your password. Please use the following verification code to proceed:\n\n"
    email_body += f"Verification Code: {verification_code}\n\n"
    email_body += "-PullBox"
    msg.body = email_body

    try:
        mail.send(msg)
        return jsonify({'message': 'Verification code sent successfully'})
    except Exception as e:
        print(e)
        return jsonify({'message': 'Verification code not sent'})


@application.route('/verify_and_change_password', methods=['POST'])
def verify_and_change_password():

    data = request.get_json()
    email = data.get('email')
    verification_code = data.get('verification_code')
    new_password = data.get('new_password')

    user = collection.find_one({'email': email})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Replace 'verification_code_field' with actual field name
    stored_verification_code = user.get('verification_code_field')
    print(stored_verification_code)
    print(verification_code)

    if verification_code == stored_verification_code:
        hashed_new_password = bcrypt.generate_password_hash(
            new_password).decode('utf-8')
        print(new_password)
        print(hashed_new_password)

        # Update user's password and clear verification code
        collection.update_one({'_id': user['_id']}, {
                              '$set': {'password': hashed_new_password, 'verification_code_field': ''}})

        return jsonify({'message': 'Password changed successfully'})

    return jsonify({'message': 'Invalid verification code'})




@application.route('/add_notification', methods=['POST'])
@jwt_required()
def add_notification():

    post_id = request.json.get('post_id')
    username = get_jwt_identity()
    msg1 = username + request.json.get('message')
    message = {'message': msg1, 'username': username, 'post_id': post_id}

    post = collection1.find_one({'_id': ObjectId(post_id)})
    reciver = post['username']
    type = request.json.get('type')
    if type == '':
        notifications = collection2.find_one({'username': reciver})
        if notifications:
            notifications['messages'].append(message)
            collection2.update_one({'username': reciver}, {
                                   '$set': notifications})
            return jsonify({'message': 'ok'})
        else:
            new_notification_object = {
                'username': reciver, 'messages': [message]}
            collection2.insert_one(new_notification_object)
            return jsonify({'message': 'ok'})

    else:
        return jsonify({'message': 'ok'})


@application.route('/get_notifications', methods=['POST'])
@jwt_required()
def get_notification():

    username = get_jwt_identity()

    type = request.json.get('type')
    if type == '':
        notifications = collection2.find_one({'username': username})
        if notifications:

            return jsonify({'messages': notifications['messages']})
        else:
            new_notification_object = {'username': username, 'messages': []}
            collection2.insert_one(new_notification_object)
            return jsonify({'message': []})

    else:
        return jsonify({'message': 'ok'})


@application.route('/delete_notifications', methods=['POST'])
@jwt_required()
def delete_notification():
    nots = request.json.get('new_list')

    username = get_jwt_identity()

    type = request.json.get('type')
    if type == '':
        notifications = collection2.find_one({'username': username})

        if notifications:
            notifications['messages'] = nots
            collection2.update_one({'username': username}, {
                                   '$set': notifications})

            return jsonify({'messages': 'deleted'})
        else:

            return jsonify({'message': 'ok'})

    else:
        return jsonify({'message': 'ok'})


@application.route('/sign_up', methods=['POST'])
def sign_up():
    email = request.json.get('email')
    password = request.json.get('password')
    username = request.json.get('username')
    profile_pic = request.json.get('pro_pic')
    name = request.json.get('name')
    urls = ['https://thums.s3.eu-central-1.amazonaws.com/images/ben1.jpg', 'https://thums.s3.eu-central-1.amazonaws.com/images/ben2.jpg',
        'https://thums.s3.eu-central-1.amazonaws.com/images/ben3.jpg', 'https://thums.s3.eu-central-1.amazonaws.com/images/ben4.jpg']

    existing_user = collection.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'Email already exists'})

    existing_username = collection.find_one({'username': username})
    if existing_username:
        return jsonify({'message': 'Username already exists'})

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    print("Hashed password:", hashed_password)

    new_user = {
        'email': email,
        'password': hashed_password,
        'username': username,
        'name': name,
        'profile_picture': random.choice(urls),
        'subscriptions': [],
        'boxes': []
    }

    collection.insert_one(new_user)

    access_token = create_access_token(identity=username, expires_delta=False)
    print(access_token + " acces tocken")
    return jsonify({'access_token': access_token, 'message': 'Login successful'}), 200


@application.route('/sign_in', methods=['POST'])
def sign_in():
    email = request.json.get('email')
    password = request.json.get('password')

    user = collection.find_one({'email': email})

    if not user or not bcrypt.check_password_hash(user['password'], password):

        return jsonify({'message': 'Invalid email or password'}), 200

    access_token = create_access_token(
        identity=user['username'], expires_delta=False)
    return jsonify({'access_token': access_token, 'message': 'Login successful'}), 200


@application.route('/pre_sign_up', methods=['POST'])
def pre_sign_up():
    email = request.json.get('email')
    password = request.json.get('password')

    existing_user = collection.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'Email already exists'}), 200

    response = make_response(jsonify({'message': 'Login successful'}))

    return response, 200


# ______________________Messages________________________________________________________________


# Add a message endpoint
@application.route('/add_message', methods=['POST'])
@jwt_required()
def add_post():
    current_user = get_jwt_identity()
    data = request.get_json()
    post_id = data.get('post_id')
    message = data.get('message')

    # Find the post with the given ID
    post = collection1.find_one({'_id': ObjectId(post_id)})

    if post:
        # Check if the username has permission to write on the post
        permissions = post['permission']
        print("post")
        print(current_user)
        print(permissions)

        if current_user in permissions or current_user == post['username']:
            dict_message = {"username": current_user, "content": message}

            # Add the message to the post's messages list
            post['messages'].append(dict_message)
            post['post'] += 1

            # Update the post in the collection
            collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
            return jsonify({'message': 'Post updated successfully'}), 200
        else:
            return jsonify({'message': 'User does not have permission to write on this post'}), 200

    return jsonify({'message': 'Post not found'}), 200


@application.route('/add_message_w', methods=['POST'])
@jwt_required()
def add_post_w():
    current_user = get_jwt_identity()
    data = request.get_json()
    post_id = data.get('post_id')
    message = data.get('message')

    # Find the post with the given ID
    post = collection3.find_one({'_id': ObjectId(post_id)})

    if post:
        # Check if the username has permission to write on the post

        print("post")
        print(current_user)

        dict_message = {"username": current_user, "content": message}

        # Add the message to the post's messages list
        post['messages'].append(dict_message)
        post['post'] += 1

        # Update the post in the collection
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
        return jsonify({'message': 'Post updated successfully'}), 200

    return jsonify({'message': 'Post not found'}), 200

# w


@application.route('/add_to_myboxes', methods=['POST'])
@jwt_required()
def add_to_myboxes():
    current_user = get_jwt_identity()
    data = request.get_json()
    post_id = data.get('post_id')

    # Find the user with the given username
    user = collection.find_one({'username': current_user})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get the user's current boxes list
    current_boxes = user.get('boxes', [])
    if post_id not in current_boxes:
        current_boxes.append(post_id)

    # Update the user's "boxes" list in the database
    collection.update_one({'_id': user['_id']}, {
                          '$set': {'boxes': current_boxes}})

    return jsonify({'message': 'Added to myBoxes successfully', 'boxes': current_boxes})


@application.route('/get_myboxes', methods=['POST'])
@jwt_required()
def get_myboxes():
    current_user = get_jwt_identity()
    print(current_user)

    # Find the user with the given username
    user = collection.find_one({'username': current_user})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Retrieve post IDs from the collection based on the current user
    post_ids_cursor = collection1.find(
        {'username': current_user}, {'_id': 1, })

    # Create a list of dictionaries containing _id and postId
    post_ids_list = [str(post['_id']) for post in post_ids_cursor]

    return jsonify({'myBoxes': post_ids_list})


@application.route('/get_user_box', methods=['POST'])
def get_user_boxes():
    data = request.get_json()
    current_user = data.get('username')
    print(current_user)

    # Find the user with the given username
    user = collection.find_one({'username': current_user})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Retrieve post IDs from the collection based on the current user
    post_ids_cursor = collection1.find(
        {'username': current_user}, {'_id': 1, })

    # Create a list of dictionaries containing _id and postId
    post_ids_list = [str(post['_id']) for post in post_ids_cursor]

    return jsonify({'myBoxes': post_ids_list})


@application.route('/delete_post', methods=['POST'])
@jwt_required()
def delete_post():
    current_user = get_jwt_identity()
    data = request.get_json()
    post_id = data.get('post_id')

    # Find the post with the given ID
    post = collection1.find_one({'_id': ObjectId(post_id)})

    if post:
        # Check if the current user has permission to delete the post
        if current_user == post.get('username'):
            # Delete the post
            collection1.delete_one({'_id': ObjectId(post_id)})
            return jsonify({'message': 'Post deleted successfully'}), 200
        else:
            return jsonify({'message': 'User does not have permission to delete this post'}), 403
    else:
        return jsonify({'message': 'Post not found'}), 404


# Subscribe


@application.route('/subscribe', methods=['POST'])
@jwt_required()
def subscribe():
    current_user = get_jwt_identity()
    data = request.get_json()
    # The single post ID the user wants to subscribe to
    post_id = data.get('post_id')
    post = collection1.find_one({'_id': ObjectId(post_id)})

    # Find the user with the given username or email
    user = collection.find_one(
        {'$or': [{'username': current_user}, {'email': current_user}]})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Update the user's subscription list with the new post ID
    current_subscriptions = user.get('subscriptions', [])
    if post_id not in current_subscriptions:
        current_subscriptions.append(post_id)
        post['subs'] += 1
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})

    # Update the user's subscriptions in the database
    collection.update_one({'_id': user['_id']}, {
                          '$set': {'subscriptions': current_subscriptions}})

    return jsonify({'message': 'Subscribed successfully'})


@application.route('/get_post', methods=['POST'])
def get_post():
    data = request.get_json()
    post_id = data.get('post_id')

    # Find the post with the given ID
    post = collection1.find_one({'_id': ObjectId(post_id)})

    if post:

        # Prepare post information to send back to the client
        post_info = {
            'title': post['title'],
            'thumbnail_link': post['thumbnail'],
            'post_id': post_id,
            'description': post['description'],
            'permissions': post['permission'],
            'username': post['username'],
            'views': post['views'],
            'subs': post['subs'],
            'posts': post['post'],
            'VIP': post['VIP']



            # Add other post properties you want to include
        }
        print(post['permission'])
        return jsonify(post_info)
    else:
        return jsonify({'error': 'Post not found'}), 400
# Get messages endpoint\


@application.route('/get_vip_post', methods=['POST'])
def get_vip_post():
    data = request.get_json()
    post_id = data.get('post_id')

    # Find the post with the given ID
    post = collection3.find_one({'_id': ObjectId(post_id)})

    if post:

        # Prepare post information to send back to the client
        post_info = {
            'title': post['title'],
            'thumbnail_link': post['thumbnail'],
            'post_id': post_id,
            'description': post['description'],
            'balance': post['balance'],
            'sales': post['sales'],
            'reveneau': post['reveneau']




        }

        return jsonify(post_info)
    else:
        return jsonify({'error': 'Post not found'}), 400
# Get messages endpoint\


@application.route('/get_messages', methods=['POST'])
def get_messages():
    data = request.get_json()
    post_id = data.get('post_id')
    page = data.get('page')  # Default page is 1
    # Updated number of messages per page is 50
    per_page = data.get('per_page')

    # Find the post with the given ID
    post = collection1.find_one({'_id': ObjectId(post_id)})

    if post:
        # Get the messages from the post
        messages = post['messages']

        # Paginate the messages
        total_messages = len(messages)
        start_index = (page - 1) * per_page
        end_index = start_index + per_page
        paginated_messages = messages[start_index:end_index]

        if not paginated_messages:  # No messages found in the requested page
            return jsonify({'error': 'No messages found'})

        return jsonify({
            'messages': paginated_messages,
            'total_messages': total_messages,
            'current_page': page,
            'messages_per_page': per_page
        })
    else:
        return jsonify({'error': 'Post not found'})


# unsubscribe
@application.route('/unsubscribe', methods=['POST'])
@jwt_required()
def unsubscribe():

    current_user = get_jwt_identity()
    data = request.get_json()

    # The single post ID the user wants to unsubscribe from
    post_id = data.get('post_id')
    post = collection1.find_one({'_id': ObjectId(post_id)})

    # Find the user with the given username or email
    user = collection.find_one(
        {'$or': [{'username': current_user}, {'email': current_user}]})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Update the user's subscription list by removing the post ID
    current_subscriptions = user.get('subscriptions', [])
    if post_id in current_subscriptions:
        current_subscriptions.remove(post_id)
        post['subs'] -= 1
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
    if not current_subscriptions:
        # 204 No Content
        return jsonify({'message': 'No subscriptions found'}), 204

    # Update the user's subscriptions in the database
    collection.update_one({'_id': user['_id']}, {
                          '$set': {'subscriptions': current_subscriptions}})

    return jsonify({'message': 'Unsubscribed successfully', 'subscriptions': current_subscriptions})


@application.route('/search_boxes', methods=['POST'])
def search_boxes():

    data = request.get_json()
    query = data.get('query')  # The search query (box title)
    page = data.get('page', 1)  # Default page is 1
    # Default number of boxes per page is 10
    per_page = data.get('per_page', 10)

    # Search for boxes matching the query in the database
    boxes = collection1.find(
        {'title': {'$regex': query, '$options': 'i'}},
        {'_id': 1, 'title': 1}
    ).limit(per_page).skip((page - 1) * per_page)

    # Convert the MongoDB Cursor to a list of dictionaries
    box_list = list(boxes)
    print(box_list)
    for box in box_list:
        box['_id'] = str(box['_id'])
    print(box_list)

    if not box_list:
        # 204 No Content
        return jsonify({'message': 'No boxes found'}), 204

    return jsonify({'boxes': box_list})

# Rest of your code...

# hello


@application.route('/add_views', methods=['POST'])
def add_view():
    data = request.get_json()
    post_id = data.get('post_id')

    # Find the post with the given ID
    post = collection1.find_one({'_id': ObjectId(post_id)})

    if post:
        # Increment the view count of the post
        post['views'] += 1
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})

        return jsonify({'message': 'View added successfully'}), 200
    else:
        return jsonify({'error': 'Post not found'}), 404

# Protected route for modifying posts


@application.route('/add_permission', methods=['post'])
@jwt_required()
def add_permission():

    data = request.get_json()
    post_id = data.get('post_id')
    username = data.get('username')
    post = collection1.find_one({'_id': ObjectId(post_id)})

    if username not in post['permission']:

        post['permission'].append(username)
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
        return jsonify({'message': 'User added to permissions'})
    else:
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
        return jsonify({'message': 'User added to permissions'})


@application.route('/modify_post', methods=['POST'])
@jwt_required()
def modify_post():
    current_user = get_jwt_identity()
    data = request.get_json()
    post_id = data.get('post_id')
    title = data.get('title')
    description = data.get('description')
    action = data.get('action')
    username = data.get('username')
    permissions = data.get('permissions')
    post = collection1.find_one({'_id': ObjectId(post_id)})
    # Find the post with the given ID

    if not post:
        return jsonify({'error': 'Post not found'}), 404

    # Check if the user has permission to modify the post
    if current_user != post.get('username'):
        return jsonify({'error': 'User does not have permission to modify this post'}), 403

    if action == 'edit_post':
        # Update post title and description
        post['title'] = title
        post['description'] = description
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
        return jsonify({'message': 'Post modified successfully'})

    elif action == 'delete_post':
        # Delete the post
        collection1.delete_one({'_id': ObjectId(post_id)})
        return jsonify({'message': 'Post deleted successfully'})

    elif action == 'add_permission':
        # Add a user to the permissions list
        permissions = post['permission']

        if username not in permissions:
            permissions.append(username)
        post['permission'] = permissions
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
        return jsonify({'message': 'User added to permissions'})
    elif action == 'set_permissions':
        # Add a user to the permissions list

        post['permission'] = permissions
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
        return jsonify({'message': 'User added to permissions'})

    elif action == 'remove_permission':
        # Remove a specific user from the permissions list
        permissions = post['permission']
        print("recived")

        if username in permissions:
            permissions.remove(username)
        post['permission'] = permissions
        collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
        return jsonify({'message': 'User removed from permissions'})

    return jsonify({'error': 'Invalid request'})


@application.route('/search_users', methods=['POST'])
def search_users():

    data = request.get_json()
    query = data.get('query')  # The search query (username or name)
    page = data.get('page')  # Default page is 1
    # Default number of users per page is 10
    per_page = data.get('per_page', 10)

    # Search for users matching the query in the database
    users = collection.find(
        {
            '$or': [
                {'username': {'$regex': query, '$options': 'i'}},
                {'name': {'$regex': query, '$options': 'i'}},

            ]
        },
        {'_id': 0, 'username': 1, 'name': 1, 'profile_picture': 1}
    ).limit(per_page).skip((page - 1) * per_page)

    # Convert the MongoDB Cursor to a list of dictionaries
    user_list = list(users)
    print(user_list)

    return jsonify({'users': user_list})


@application.route('/get_subscriptions', methods=['GET'])
@jwt_required()
def get_subscriptions():
    current_user = get_jwt_identity()

    # Find the user with the given username or email
    user = collection.find_one(
        {'$or': [{'username': current_user}, {'email': current_user}]})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get the user's subscriptions from the database
    subscriptions = user.get('subscriptions', [])
    if not subscriptions:
        # 204 No Content
        return jsonify({'message': 'No subscriptions found'}), 204

    return jsonify({'subscriptions': subscriptions})

# Get user information based on username


@application.route('/get_user', methods=['POST'])
def get_user():
    username = request.json.get('username')

    user = collection.find_one({'username': username})
    if not user:
        # If user is not found by username, try to find by email
        user = collection.find_one({'email': username})

    if user:
        user_info = {

            'name': user['name'],
            'username': user['username'],
            'profile_picture': user['profile_picture']
        }
        return jsonify(user_info)
    else:
        return jsonify({'error': 'User not found'})


@application.route('/update_profile', methods=['POST'])
@jwt_required()
def update_profile():
    current_user = get_jwt_identity()
    data = request.get_json()
    new_profile_picture = data.get('profile_picture')
    new_name = data.get('name')

    # Find the user with the given username
    user = collection.find_one({'username': current_user})
    posts = collection1.find({'username': current_user})
    print(posts)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Update the user's profile picture and name
    user['profile_picture'] = new_profile_picture
    user['name'] = new_name
    try:

        for post in posts:
            post['profile_image'] = new_profile_picture
            post['name'] = new_name
            collection1.update_one({'_id': post['_id']}, {'$set': post})

    except Exception as e:
        print(e)
    posts = collection1.find({'username': current_user})
    print(posts)

    collection.update_one({'_id': user['_id']}, {'$set': user})
    user = collection.find_one({'username': current_user})
    print(user)
    print(new_profile_picture)

    return jsonify({'message': 'Profile updated successfully'})


