
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <gtk/gtk.h>
#include "sniffer.h"

FILE*fp;

static gboolean time_handler(GtkWidget *);
int cntk = 0;
typedef struct
{
        GSList *windows;
        
        /* etc... whatever application vars you need */
} MyApp;




int getint(char* s){
	int i=0,num = 0;
	while(s[i]>='0' && s[i]<='9'){
		num = num*10+ (s[i]-'0');
		i++;
	}
	return num;
}


char * call2(char *str,char *str2, size_t size)
{
    if (size) 
    {
        --size;
		size_t n;
        for ( n = 0; n < size || str2[n] != '\0'; n++)
            str[n] = str2[n];
        str[size] = '\0';
    }
    return str;
}

char * call(char *str,size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (size) 
    {
        --size;
		size_t n;
        for ( n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}


void on_window_destroy (GtkWidget *widget, MyApp *app)
{
    app->windows = g_slist_remove (app->windows, widget);
    
    if (g_slist_length (app->windows) == 0)
    {
            /* last window was closed... exit */
            
            g_debug ("Exiting...");
            g_slist_free (app->windows);
            gtk_main_quit ();
    }
}

void on_add_button_clicked (GtkWidget *widget, MyApp *app)
{
    GtkWidget *window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    GtkWidget *button = gtk_button_new_from_stock (GTK_STOCK_ADD);
    gchar *title;

	char* s1 = (char*)gtk_button_get_label ((GtkButton*)widget);
	//printf("~~%d_%s\n",getint(s1),s1);
	
	
    app->windows = g_slist_prepend (app->windows, window);
    char * fname[10];
	sprintf(fname,"dump/%d.txt",getint(s1));

	int len = 4096;
	char content[len];
	FILE * f = fopen(fname,"r");
	//fgets(content, sizeof(content), f);
	int c,z = 0;
	while ((c = fgetc(f)) != EOF)
	{
	  content[z++] = (char)c;
	}
	content[z] = '\0';
	//fscanf(f, "%s", content)

	//printf("%s\n",content);
    gtk_button_set_label (button,
		content);
	gtk_window_set_default_size(GTK_WINDOW(window), 200, 200);
  	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    gtk_container_set_border_width (GTK_CONTAINER (window), 25);
    gtk_container_add (GTK_CONTAINER (window), button);
    title = g_strdup_printf ("Window %d", g_slist_length (app->windows));
    gtk_window_set_title (GTK_WINDOW (window), title);
    g_free (title);
        
    /* connect callbacks to signals */
        
    g_signal_connect (G_OBJECT (window), "destroy",G_CALLBACK (on_window_destroy), app);
        
    //g_signal_connect (G_OBJECT (button), "clicked", G_CALLBACK (on_add_button_clicked), app);
        
    gtk_widget_show_all (window);     
}

int main (int argc, char *argv[])
{	
	printf("###################################################################\n");
	printf("Press Control-C to stop capturing packets and for GUI visualization\n");
	printf("###################################################################\n");
	caller();
    MyApp *app;
    
    gtk_init (&argc, &argv);
    app = g_slice_new (MyApp);
    app->windows = NULL;

	GtkWidget *window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	GtkWidget *button_box =  gtk_button_box_new(GTK_ORIENTATION_VERTICAL);// (GTK_ORIENTATION_HORIZONTAL);
	GtkWidget *scrolled_window;

    gchar *title;

    app->windows = g_slist_prepend (app->windows, window);
	scrolled_window = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_window), 
                                  GTK_POLICY_AUTOMATIC, 
                                  GTK_POLICY_AUTOMATIC); 
        

        
	
    gtk_container_set_border_width (GTK_CONTAINER (window), 25);
	gtk_window_set_default_size(GTK_WINDOW(window), 600, 600);
  	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_container_add (GTK_CONTAINER (scrolled_window), 
                                         button_box);
	//gtk_container_add (GTK_CONTAINER (window), button_box);
	
	FILE*fp = fopen("log.txt","r");
	char ch[500],c;


	if (fp != NULL)
	{
        while (fscanf(fp, "%[^\n]%c", ch, &c)==2)
        {
            char *temp = (char*)malloc(sizeof ch);
            strcpy(temp, ch);
            //do something
            //printf("%s%c\n", ch,c);
	    	GtkWidget *button = gtk_button_new_from_stock (GTK_STOCK_ADD);
			//const gchar label[1000] ;
			//char * s1 = table[sno-cntk];
			//label = s1;
			//call2(label,table[sno-cntk],1000);
			//call(label,20);
			gtk_button_set_label (button,ch);
			gtk_widget_set_size_request(button, 100, 50);
		 	//button = gtk_button_new_with_label ("Hello World");
			gtk_container_add (GTK_CONTAINER (button_box), button);
			g_signal_connect (G_OBJECT (button), "clicked", G_CALLBACK (on_add_button_clicked), app);
            free(temp);
        }
        fclose (fp);
    }

	gtk_container_add (GTK_CONTAINER (window), scrolled_window);

    title = g_strdup_printf ("Window %d", g_slist_length (app->windows));
    gtk_window_set_title (GTK_WINDOW (window), title);
    g_free (title);
    

    
    g_signal_connect (G_OBJECT (window), "destroy",G_CALLBACK (on_window_destroy), app);

	//g_timeout_add(1000, (GSourceFunc) time_handler, (gpointer) button_box);           
    gtk_widget_show_all (window);     
    //on_add_button_clicked (NULL, app);
    
    gtk_main ();
    g_slice_free (MyApp, app);
        
    return 0;               
}





























static gboolean time_handler(GtkWidget *button_box)
{
	/*int raw_socket;
	raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	unsigned char frame[65535];

	struct timeval stop, start;
	gettimeofday(&start, NULL);

	if(raw_socket < 0)
	{
		printf("Unable to open socket\n");
		return 0;
	}
	printf("open socket\n");

	//int sno = 1;
	//fp = fopen("as.txt","w+");
	int cnt = sno + 2;
	while(sno<cnt)
	{
		int size = recv(raw_socket, frame, 1024, 0);
		gettimeofday(&stop, NULL);
		//printf("%-6d", sno++);
		analyse_summary(frame, size);
		// printf("\n");
		// analyse(frame, size);
	}






	cntk = sno - cntk;
	while(cntk>0){
		GtkWidget *button = gtk_button_new_from_stock (GTK_STOCK_ADD);
		const gchar label[10];
		call(label,10);
		gtk_button_set_label (button,label);
 	//button = gtk_button_new_with_label ("Hello World");
		gtk_container_add (GTK_CONTAINER (button_box), button);
		g_signal_connect (G_OBJECT (button), "clicked", G_CALLBACK (on_add_button_clicked), button);
		cntk--;
	}
	//cntk++;

                                       
        gtk_widget_show_all (button_box); 


    return TRUE;*/
}
