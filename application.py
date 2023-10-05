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


# Set the SSL certificate file location to resolve any SSL certificate issues
os.environ['SSL_CERT_FILE'] = certifi.where()

application = Flask(__name__)
bcrypt = Bcrypt(application)
jwt = JWTManager(application)

# Connect to MongoDB
try:
    client = pymongo.MongoClient(
        "mongodb+srv://Mark_Jeff:1234@cluster0.0jh9bwk.mongodb.net/?retryWrites=true&w=majority")
    db = client.get_database('test')
    print("Connected")
    collection = db.users
    collection1 = db.posts

    collections = collection.find()
    print("Connected")

except pymongo.errors.ConnectionFailure as e:
    print("Could not connect to MongoDB: %s" % e)


@application.route('/sign_up', methods=['POST'])
def sign_up():
    email = request.json.get('email')
    password = request.json.get('password')
    username = request.json.get('username')
    profile_pic = request.json.get('pro_pic')
    name = request.json.get('name')
    print(name)

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
        'profile_picture': 'http://www.goodmorningimagesdownload.com/wp-content/uploads/2021/12/Best-Quality-Profile-Images-Pic-Download-2023.jpg',
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

        if current_user in permissions:
            dict_message = {"username": current_user, "content": message}

            # Add the message to the post's messages list
            post['messages'].append(dict_message)

            # Update the post in the collection
            collection1.update_one({'_id': ObjectId(post_id)}, {'$set': post})
            return jsonify({'message': 'Post updated successfully'}), 200
        else:
            return jsonify({'message': 'User does not have permission to write on this post'}), 200

    return jsonify({'message': 'Post not found'}), 200


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

    # Find the user with the given username or email
    user = collection.find_one(
        {'$or': [{'username': current_user}, {'email': current_user}]})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Update the user's subscription list with the new post ID
    current_subscriptions = user.get('subscriptions', [])
    if post_id not in current_subscriptions:
        current_subscriptions.append(post_id)

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
            'permissions': post['permission']



            # Add other post properties you want to include
        }
        print(post['permission'])
        return jsonify(post_info)
    else:
        return jsonify({'error': 'Post not found'})
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

    # Find the user with the given username or email
    user = collection.find_one(
        {'$or': [{'username': current_user}, {'email': current_user}]})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Update the user's subscription list by removing the post ID
    current_subscriptions = user.get('subscriptions', [])
    if post_id in current_subscriptions:
        current_subscriptions.remove(post_id)
    if not current_subscriptions:
        # 204 No Content
        return jsonify({'message': 'No subscriptions found'}), 204

    # Update the user's subscriptions in the database
    collection.update_one({'_id': user['_id']}, {
                          '$set': {'subscriptions': current_subscriptions}})

    return jsonify({'message': 'Unsubscribed successfully', 'subscriptions': current_subscriptions})


# ______________________________Change Posts_________________________________


# Protected route for modifying posts
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

    # Find the post with the given ID
    post = collection1.find_one({'_id': ObjectId(post_id)})

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


application.config['SECRET_KEY'] = secret_key
