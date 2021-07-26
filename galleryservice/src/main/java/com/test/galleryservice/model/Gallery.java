package com.test.galleryservice.model;

import java.util.List;

public class Gallery {
    int id;
    List<Object> images;

    public Gallery(List<Object> images) {
        this.images = images;
    }

    public Gallery() {
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public List<Object> getImages() {
        return images;
    }

    public void setImages(List<Object> images) {
        this.images = images;
    }
}
