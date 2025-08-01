#include "tester.h"

#define TRAIN_DATASET "data/traindata.json"
#define TEST_DATASET  "data/testdata.json"

#define TEST_CLASSIFIER "data/test_classifier.json"

int test_training() {
    classifier_t* classifier = NULL;

    // Create a new classifier without models
    classifier = classifier_init(0);

    if (classifier == NULL) {
        printf("Error: classifier is NULL\n");
        return 1;
    }

    // Get train data
    json_t* root;
    json_error_t error;

    root = json_load_file(TRAIN_DATASET, 0, &error);

    if(!root) {
        printf("Error: on line %d: %s", error.line, error.text);
        return 1;
    }

    json_t* datasets = json_object_get(root, "datasets");

    for (size_t i = 0; i < json_array_size(datasets); i++) {
        json_t* dataset;

        dataset = json_array_get(datasets, i);
        json_t* data = json_object_get(dataset, "data");
        json_t* label = json_object_get(dataset, "model_label");
        uint64_t train_set_len = json_array_size(data);
        uint64_t* train_set = calloc(train_set_len, sizeof(uint64_t));

        // Prepare train data
        for (size_t j = 0; j < train_set_len; j++) {
            json_t* key = json_array_get(data, j);
            train_set[j] = json_integer_value(key);
        }
        const char* label_value = json_string_value(label);

        classifier_add_model(classifier, label_value);

        classifier_add_dataset(classifier, label_value, train_set, train_set_len);

        // Clean up..
        free(train_set);

    }
    json_decref(root);


    // Train classifier
    classifier_train(classifier);

    // Get test data
    root = json_load_file(TRAIN_DATASET, 0, &error);

    if(!root) {
        printf("Error: On line %d: %s", error.line, error.text);
        return 1;
    }

    datasets = json_object_get(root, "datasets");

    for (size_t i = 0; i < json_array_size(datasets); i++) {
        json_t* dataset;

        dataset = json_array_get(datasets, i);
        json_t* data = json_object_get(dataset, "data");
        json_t* label = json_object_get(dataset, "model_label");
        uint64_t test_set_len = json_array_size(data);
        uint64_t* test_set = calloc(test_set_len, sizeof(uint64_t));

        // Prepare test data
        for (size_t j = 0; j < test_set_len; j++) {
            json_t* key = json_array_get(data, j);
            test_set[j] = json_integer_value(key);
        }
        const char* label_value = json_string_value(label);

        int bm_idx = classifier_score_dataset(classifier, test_set, test_set_len);

        if (bm_idx == -1) {
            printf("No model found for testset %zu\n", i);
        } else if (strncmp(classifier->models[bm_idx].label, label_value, MAX_LABEL_SIZE) == 0) {
            printf("Correct classification for testset %zu\n", i);
        } else {
            printf("Wrong classificaion for testset %zu!\n"\
                    "Expected %s, got: %s\n", i, label_value, classifier->models[bm_idx].label);
        }
        // Clean up..
        free(test_set);

    }
    json_decref(root);

    classifier_destroy(classifier);
    return 0;

}

int test_read_write_json() {
    classifier_t* cls = NULL;

    char* json_encoded = NULL;
    FILE *json = fopen(TEST_CLASSIFIER, "r");
    if (json != NULL) {
        if (fseek(json, 0, SEEK_END) == 0) {
            size_t buf_size = ftell(json);
            if (buf_size == -1) {
                //ERROR
            }
            json_encoded = calloc(buf_size+1, sizeof(char));
            if (json_encoded == NULL) {
                //ERROR
            }
            if (fseek(json, 0, SEEK_SET) != 0) {
                //ERROR
            }
            size_t bytes_read = fread(json_encoded, sizeof(char), buf_size, json);
            if (bytes_read == 0) {
                //ERROR
            } else {
               json_encoded[bytes_read]  = '\0';
            }
        }
        fclose(json);
    } else {
        return 1;
    }


    cls = classifier_from_json(json_encoded);

    if (cls == NULL) {
        printf("Error: Could not read classifier from file\n");
        return 1;
    }

    json_t *cls_json = classifier_to_json(cls);
    if (!cls_json) {
        printf("Error: Could not convert classifier to json\n");
        return 1;
    }
    json_decref(cls_json);

    classifier_destroy(cls);
    free(json_encoded);

    return 0;
}

int main() {
    //TODO use tnt like function array..
    if (test_training() == 1) {
        return 1;
    }
    if (test_read_write_json() == 1) {
        return 1;
    }
    return 0;
}
