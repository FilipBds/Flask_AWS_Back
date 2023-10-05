import certifi
import os
import pymongo
import math
import random
from flask import Flask, jsonify, request
import numpy as np
import json
from bson import json_util, ObjectId
from bson.raw_bson import RawBSONDocument

# Set the SSL certificate file location to resolve any SSL certificate issues
os.environ['SSL_CERT_FILE'] = certifi.where()

app = Flask(__name__)

# Connect to MongoDB
try:
    client = pymongo.MongoClient(
        "mongodb+srv://Mark_Jeff:1234@cluster0.0jh9bwk.mongodb.net/?retryWrites=true&w=majority")
    db = client.get_database('test')
    print("Connected")
    collection = db.posts

    collections = collection.find()
    print("Connected")

except pymongo.errors.ConnectionFailure as e:
    print("Could not connect to MongoDB: %s" % e)


# Endpoint for starting


# Endpoint for getting recommendations
@app.route('/rec', methods=['POST'])
def get_recommendations_handler():
    # Get user ID and clusters
    user_id = request.json.get('user_id')
    clusters = request.json.get('list')

    # Calculate number of posts to generate for each category
    num_posts = request.json.get('num_posts')
    print(num_posts)
    medium_posts = []
    excellent_posts = []
    additional_posts = []
    num_excellent_posts = math.ceil(num_posts * 0.65)  # 65% excellent posts
    # Remaining posts will be medium
    num_medium_posts = num_posts - num_excellent_posts

    # Check if top_clusters list is empty
    if not clusters:
        # Get random clusters from MongoDB
        random_clusters = collection.distinct("cluster")
        random_clusters = random.sample(random_clusters, 3)
        excellent_posts = []
        for cluster in random_clusters:
            pipeline = [
                {"$match": {"cluster": int(cluster), "engagement": {
                    "$ne": "bad"}}},
                {"$project": {"messages": 0}},
                {"$sample": {"size": 1}}
            ]
            post = collection.aggregate(pipeline)
            excellent_posts.extend(post)
    else:
        # Get posts for top clusters
        scores = list(clusters.values())
        q2, q3 = np.percentile(scores, [35, 65])
        top_clusters = [k for k, v in clusters.items() if v >= q3]
        medium_clusters = [k for k, v in clusters.items() if q2 <= v < q3]

        num_additional_posts = round(math.ceil(num_posts * 0.2))
        new_cluster = collection.distinct(
            "cluster", {"cluster": {"$nin": top_clusters + medium_clusters}})
        if new_cluster:
            new_cluster = random.choice(new_cluster)
            new_cluster_posts = collection.find({"cluster": new_cluster, "engagement": {
                                                "$ne": "bad"}},  {"messages": 0}).limit(num_additional_posts)
            additional = list(new_cluster_posts)
            for post in additional:
                additional_posts.append(post)
                if len(additional_posts) == num_additional_posts:
                    break

        else:
            additional_posts = []

        # Get excellent posts

        for cluster in top_clusters:
            pipeline = [
                {"$match": {"cluster": int(
                    cluster), "engagement": "excellent"}},
                {"$project": {"messages": 0}},
                {"$sample": {"size": num_excellent_posts}}
            ]
            posts = collection.aggregate(pipeline)
            for post in posts:
                excellent_posts.append(post)
                if len(excellent_posts) == int(num_excellent_posts):
                    break

        # If there are not enough excellent posts, supplement with medium posts
        if len(excellent_posts) < num_excellent_posts:
            num_remaining_posts = num_excellent_posts - len(excellent_posts)
            for cluster in top_clusters:
                pipeline = [
                    {"$match": {"cluster": int(
                        cluster), "engagement": "medium"}},
                    {"$project": {"messages": 0}},
                    {"$sample": {"size": num_remaining_posts}}
                ]
                posts = collection.aggregate(pipeline)
                for post in posts:
                    excellent_posts.append(post)
                    if len(excellent_posts) == num_excellent_posts:
                        break

        # Get medium posts

        for cluster in medium_clusters:
            pipeline = [
                {"$match": {"cluster": int(cluster), "engagement": "medium"}},
                {"$project": {"messages": 0}},
                {"$sample": {"size": num_medium_posts}}
            ]
            posts = collection.aggregate(pipeline)
            for post in posts:
                medium_posts.append(post)
                if len(medium_posts) == num_medium_posts:
                    break

        # If there are not enough medium posts, supplement with excellent posts
        if len(medium_posts) < num_medium_posts:
            num_remaining_posts = num_medium_posts - len(medium_posts)
            for cluster in medium_clusters:
                pipeline = [
                    {"$match": {"cluster": int(
                        cluster), "engagement": "excellent"}},
                    {"$project": {"messages": 0}},
                    {"$sample": {"size": num_remaining_posts}}
                ]
                posts = collection.aggregate(pipeline)
                for post in posts:
                    medium_posts.append(post)
                    if len(medium_posts) == num_medium_posts:
                        break

    all_posts = []
    all_posts.extend(excellent_posts)
    all_posts.extend(medium_posts)

    # Check if the number of posts is smaller than num_posts
    if len(all_posts) < num_posts:
        remaining_posts = num_posts - len(all_posts)
        pipeline = [
            {"$match": {"engagement": {"$ne": "bad"}}},
            {"$project": {"messages": 0}},
            {"$sample": {"size": remaining_posts}}
        ]
        additional_posts = list(collection.aggregate(pipeline))
        if len(additional_posts) >= remaining_posts:
            additional_posts = random.sample(additional_posts, remaining_posts)
        else:
            pass
        all_posts.extend(additional_posts)

    for post in all_posts:
        post['_id'] = str(post['_id'])

    response = {'user_id': user_id, 'recommendations': all_posts}

    return jsonify(response)

# -------------------------------------------------------------------------------


@app.route('/update_scores', methods=['POST'])
def update_scores_handler():
    payload = request.get_json()
    scores_dict = payload.get('scores_dict')

    for post_id, score in scores_dict.items():
        post = collection.find_one({'_id': ObjectId(post_id)})
        if post:
            current_score = post.get('score', 0)
            current_num_ratings = post.get('num_ratings', 0)

            new_score = round(
                (current_score * current_num_ratings + score) / (current_num_ratings + 1), 2)
            new_num_ratings = current_num_ratings + 1

            collection.update_one(
                {'_id': ObjectId(post_id)},
                {'$set': {'score': new_score, 'num_ratings': new_num_ratings}}
            )

            count_thresholds = [10, 20, 40, 80, 160, 320, 640, 1000, 2000, 5000, 100000, 500000,
                                1000000, 50000000, 10000000, 50000000, 100000000]  # Adjust these thresholds as needed
            if current_num_ratings in count_thresholds:
                average_score = new_score
                engagement = get_engagement_metric(average_score)
                collection.update_one(
                    {'_id': ObjectId(post_id)},
                    {'$set': {'engagement': engagement}}
                )

    return 'Scores updated successfully'


def get_engagement_metric(score):
    if score >= 6:
        return 'excellent'
    elif score >= 0.4:
        return 'medium'
    else:
        return 'bad'


#app run
