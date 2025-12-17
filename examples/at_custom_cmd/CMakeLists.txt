
file(GLOB_RECURSE srcs *.c)

set(includes "include"
	     "${IDF_PATH}/components/bt/host/bluedroid/stack/include/stack"
             "${IDF_PATH}/components/bt/host/bluedroid/common/include"
	     "${IDF_PATH}/components/bt/host/bluedroid/common/include/common"
	     "${IDF_PATH}/components/bt/common/include"
	     "${IDF_PATH}/components/bt/host/bluedroid/stack/include"
	     "${IDF_PATH}/components/bt/host/bluedroid/stack/rfcomm/include")

# Add more required components you need here, separated by spaces
set(require_components at freertos nvs_flash bt)

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS ${includes}
    REQUIRES ${require_components})

idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE TRUE)

target_link_libraries(${COMPONENT_LIB} INTERFACE "-u esp_at_custom_cmd_register")