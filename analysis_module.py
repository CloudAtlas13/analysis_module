from kafka import KafkaConsumer
from kafka import KafkaProducer

import numpy as np
import time
import tensorflow as tf
import pickle
import sklearn


import os


def write_to_file(data_vector, path, mode="a"):
    check_path(path, mode)
    try:
        output_file = open(path, mode)
    except IOError:
        output_file = open(path, 'w')

    size = len(data_vector)

    for index, item in enumerate(data_vector):
        if index == size-1:
            output_file.write(str("{}".format(item)))
        else:
            output_file.write(str("{}".format(item)) + ",")

    output_file.write("\n")
    output_file.close()


def check_path(path, mode):
    directory = path[:path.rfind("/")]
    if mode == "a" or mode == "w":
        if not os.path.isdir(directory):
            os.mkdir(directory)


def pickle_save(path, rf):
    with open(path, 'wb') as f:
        pickle.dump(rf, f)


def pickle_load(path):
    with open(path, 'rb') as f:
        rf = pickle.load(f)
    return rf


"""
Función que guarda un modelo hecho en tensorflow
    session: sesión del modelo tf, debe estar abierta
    filename: path en el que se desea guardar
    global_n: id del modelo (o del estado del mismo si procede)
return:
    save_path: path del modelo guardado (con id)
"""


def save_model(session, filename, global_n):
    saver = tf.train.Saver()
    save_path = saver.save(session, filename, global_step=global_n)
    print("Model saved to %s" % save_path)
    return save_path


"""
Función que carga un modelo tensorflow en el programa
    filename: path del modelo a cargar (con id)
return:
    session: sesión de del modelo tf
    tf_test_dataset: variable input para test del modelo
    test_prediction: variable output para test del modelo
"""


def load_model(filename):
    session = tf.Session()
    filenamemeta = filename + '.meta'
    new_saver = tf.train.import_meta_graph(filenamemeta)
    new_saver.restore(session, filename)
    tf_train_dataset = session.graph.get_tensor_by_name("trainds_input:0")
    tf_train_labels = session.graph.get_tensor_by_name("trainlb_input:0")
    tf_valid_dataset = session.graph.get_tensor_by_name("valid_input:0")
    tf_test_dataset = session.graph.get_tensor_by_name("test_input:0")
    train_prediction = session.graph.get_tensor_by_name("train_output:0")
    valid_prediction = session.graph.get_tensor_by_name("valid_output:0")
    test_prediction = session.graph.get_tensor_by_name("test_output:0")

    return session, tf_train_dataset, tf_train_labels, tf_valid_dataset, tf_test_dataset, train_prediction, \
           valid_prediction, test_prediction


"""
A comentar
"""

def save_metrics_to_file(filePath, description, id, metrics):
    metrics.insert(0, description)
    metrics.insert(0, id)
    metrics.insert(0, int(time.time()))
    write_to_file(metrics,filePath)

"""
A comentar
"""


def save_logs(filePath, description1, description2, id):
    output = open(filePath, 'a')
    output.write(str(id) + ';')
    for log in description1:
        output.write(str("{:.3f}".format(log)) + ';')
    output.write('\n')

    output.close()



protocol_map = {6: 'tcp', 17: 'udp'}
model_list = ['random_forest']
classification_list= ['binary', 'multi']

multi_labels_list = ['Normal', 'Exploits', 'Reconnaissance', 'DoS', 'Generic', 'Shellcode', 'Fuzzers', 'Worms', 'Backdoors', 'Analysisi']


def analyze(parsed_trace, protocol):
    total_decisions=len(model_list)*len(classification_list)
    decisions=[]
    decision_makers = []
    for model in model_list:
        for classification in classification_list:
            route='../data/models/'+protocol_map[protocol]+'/'+model+'/'+classification
            algorithm=pickle_load(route)
            reshaped_trace = parsed_trace.reshape(-1, parsed_trace.shape[0])
            prediction = algorithm.predict(reshaped_trace)[0][1]
            if classification == 'multi':
                decisions.append(multi_labels_list[int(prediction)])
            else:
                decisions.append(int(prediction))
            decision_makers.append(protocol_map[protocol]+'/'+model+'/'+classification)
    return decisions, decision_makers



consumer = KafkaConsumer('connections',
                         bootstrap_servers=['10.40.39.22:1025'])

producer = KafkaProducer(bootstrap_servers='10.40.39.22:1025')


print('Started Consumer')
for message in consumer:
    full_parsed_trace = message.value.decode('utf-8').replace("[", "").replace("]", "").replace('"',"").replace("'","").split(' ')
    parsed_trace = np.array([])
    for i in range(len(full_parsed_trace)-1):
        parsed_trace=np.append(parsed_trace,full_parsed_trace[i])
    protocol=int(full_parsed_trace[len(parsed_trace)])
    parsed_trace=parsed_trace.astype(np.float32)
    decisions, decision_makers=analyze(parsed_trace,protocol)
    print(parsed_trace)
    print(decision_makers, decisions)